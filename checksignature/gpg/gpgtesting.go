package gpg

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
	"github.com/ICL-ml4csec/msc-hmj24/trustpolicies"
)

// GitHubCommitVerification represents GitHub's verification status
type GitHubCommitVerification struct {
	Verified  bool   `json:"verified"`
	Reason    string `json:"reason"`
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
}

// GitHubCommitData represents commit data from GitHub API
type GitHubCommitData struct {
	SHA    string `json:"sha"`
	Commit struct {
		Verification GitHubCommitVerification `json:"verification"`
		Message      string                   `json:"message"`
		Author       struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commit"`
	Author struct {
		Login string `json:"login"`
	} `json:"author"`
}

// VerifyWithGitHubAPI uses GitHub's API to check signature verification
// This is more reliable in CI environments than local GPG
func VerifyWithGitHubAPI(repo, sha, token string) (types.SignatureStatus, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, sha)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return types.VerificationError, "", fmt.Errorf("failed to create request: %v", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return types.VerificationError, "", fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return types.VerificationError, "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var commitData GitHubCommitData
	if err := json.NewDecoder(resp.Body).Decode(&commitData); err != nil {
		return types.VerificationError, "", fmt.Errorf("failed to decode response: %v", err)
	}

	return classifyGitHubVerification(commitData.Commit.Verification)
}

// classifyGitHubVerification maps GitHub's verification reasons to our types
func classifyGitHubVerification(verification GitHubCommitVerification) (types.SignatureStatus, string, error) {
	if verification.Verified {
		return types.ValidSignature, "GitHub verified signature", nil
	}

	reason := strings.ToLower(verification.Reason)
	output := fmt.Sprintf("GitHub verification failed: %s", verification.Reason)

	switch reason {
	case "unsigned":
		return types.UnsignedCommit, output, nil
	case "gpgverify_unknown_public_key":
		return types.MissingPublicKey, output, nil
	case "gpgverify_unverified_email":
		return types.EmailNotMatched, output, nil
	case "gpgverify_unavailable":
		return types.VerificationError, output, nil
	case "bad_email":
		return types.EmailNotMatched, output, nil
	case "unverified_email":
		return types.EmailNotMatched, output, nil
	case "no_user":
		return types.ValidSignatureButUnregisteredKey, output, nil
	case "unknown_signature_type":
		return types.InvalidSignature, output, nil
	case "malformed_signature":
		return types.InvalidSignature, output, nil
	default:
		return types.VerificationError, output, nil
	}
}

// HybridVerify combines GitHub API verification with local GPG as fallback
func HybridVerify(raw []byte, sha string, config types.LocalCheckConfig) (types.SignatureStatus, string, error) {
	// First try GitHub API verification
	if config.Token != "" && config.Repo != "" && sha != "" {
		githubStatus, githubOutput, githubErr := VerifyWithGitHubAPI(config.Repo, sha, config.Token)

		// If GitHub verification succeeds, use it
		if githubErr == nil && (githubStatus == types.ValidSignature || githubStatus == types.UnsignedCommit) {
			return githubStatus, fmt.Sprintf("GitHub API: %s", githubOutput), nil
		}

		// If GitHub verification fails but provides useful info, use it for some cases
		if githubErr == nil {
			switch githubStatus {
			case types.MissingPublicKey, types.EmailNotMatched, types.InvalidSignature:
				return githubStatus, fmt.Sprintf("GitHub API: %s", githubOutput), nil
			}
		}
	}

	return performLocalGPGVerification(raw, sha, config)
}

// performLocalGPGVerification is your existing verification logic
func performLocalGPGVerification(raw []byte, sha string, config types.LocalCheckConfig) (types.SignatureStatus, string, error) {
	// fallback when GitHub API doesn't work
	content := string(raw)

	// Extract the PGP signature and payload from the commit content
	signature, payload, found := ExtractSignatureFromCommit(content)
	if !found {
		return types.UnsignedCommit, "No PGP signature found", nil
	}

	// Extract public key and key ID from signature
	publicKey, keyID, err := ExtractPublicKeyFromSignature(signature)

	// Check key age if we have a key ID
	if keyID != "" {
		createdAt, err := trustpolicies.GetPGPKeyCreationTime(keyID)
		if err == nil {
			if config.KeyCreationCutoff != nil && createdAt.After(*config.KeyCreationCutoff) {
				return types.InvalidSignature, fmt.Sprintf("Key %s created too recently (%s)", keyID, createdAt.Format(time.RFC3339)), nil
			}
		}
	}

	// Try to import the public key if we found one
	var keyImported bool
	if err == nil && publicKey != "" {
		if importErr := ImportKeyDirectly(publicKey); importErr == nil {
			keyImported = true
		}
	}

	// Perform GPG verification
	status, output, verifyErr := performGPGVerification(signature, payload)

	// Check for GitHub automated commits
	if trustpolicies.IsGitHubAutomatedCommit(output, content, nil) {
		return types.GitHubAutomatedSignature, output, verifyErr
	}

	// Additional checks for valid signatures
	if status == types.ValidSignature {
		// Check email matching
		mismatch, signerEmail, authorEmail := utils.CheckEmailMismatch(raw, output)
		if mismatch {
			return types.EmailNotMatched, fmt.Sprintf("Signer <%s> does not match author <%s>", signerEmail, authorEmail), verifyErr
		}

		// Check GitHub authorization if configured
		if config.Token != "" && config.Repo != "" && sha != "" && keyID != "" {
			authStatus, authMessage, authErr := ValidateAuthorization(keyID, config.Repo, sha, config.Token)
			if authStatus != types.ValidSignature {
				return authStatus, authMessage, authErr
			}
			if authMessage != "" {
				fmt.Print(authMessage)
			}
		}
	}

	// Handle missing public key case with imported key
	if status == types.MissingPublicKey && keyImported {
		return types.MissingPublicKey, fmt.Sprintf("PGP signature found with key ID %s, but verification failed: %s", keyID, output), verifyErr
	}

	// For now, return a placeholder - you'd move your existing logic here
	return types.VerificationError, "Local GPG verification not implemented in this example", fmt.Errorf("fallback needed")
}
