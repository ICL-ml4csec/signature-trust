package gpg

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
	"github.com/ICL-ml4csec/msc-hmj24/trustpolicies"
)

// Verify performs complete GPG signature verification
func Verify(raw []byte, sha string, config types.LocalCheckConfig) (types.SignatureStatus, string, error) {
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
		if status == types.ValidSignature {
			if config.Token != "" && config.Repo != "" && sha != "" && keyID != "" {
				authStatus, authMessage, authErr := ValidateAuthorization(keyID, config.Repo, sha, config.Token)
				if authErr != nil {
					// Don’t downgrade to error – keep it valid but log
					return types.ValidSignature, fmt.Sprintf("Authorization check warning: %v", authErr), nil
				}
				return authStatus, authMessage, authErr
			}
		}

	}

	// Handle missing public key case with imported key
	if status == types.MissingPublicKey && keyImported {
		return types.MissingPublicKey, fmt.Sprintf("PGP signature found with key ID %s, but verification failed: %s", keyID, output), verifyErr
	}

	return status, output, verifyErr
}

// performGPGVerification runs `gpg --verify` on the extracted payload and signature.
// It creates temporary files for compatibility with gpg CLI, then parses the result.
func performGPGVerification(signature, payload string) (types.SignatureStatus, string, error) {
	// Create temporary files for signature and payload
	sigFile, err := os.CreateTemp("", "*.sig")
	if err != nil {
		return types.VerificationError, "", err
	}
	defer os.Remove(sigFile.Name())
	defer sigFile.Close()

	payloadFile, err := os.CreateTemp("", "*.txt")
	if err != nil {
		return types.VerificationError, "", err
	}
	defer os.Remove(payloadFile.Name())
	defer payloadFile.Close()

	// Write signature and payload to files
	if _, err := sigFile.Write([]byte(signature)); err != nil {
		return types.VerificationError, "", err
	}
	sigFile.Close()

	if _, err := payloadFile.Write([]byte(payload)); err != nil {
		return types.VerificationError, "", err
	}
	payloadFile.Close()

	// Execute GPG verification
	cmd := exec.Command("gpg", "--verify", sigFile.Name(), payloadFile.Name())
	output, err := cmd.CombinedOutput()

	status := ClassifySignature(string(output))
	return status, string(output), err
}
