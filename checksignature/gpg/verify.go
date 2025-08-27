package gpg

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
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

	fmt.Printf("[DEBUG][PGP] sha=%s keyID(extracted)=%s err=%v\n", sha, keyID, err)
	fmt.Printf("[DEBUG][PGP] repo=%s token?=%t timeCutoff?=%t keyAgeCutoff?=%t\n",
		config.Repo, config.Token != "", config.TimeCutoff != nil, config.KeyCreationCutoff != nil)

	// Try to import the public key if we found one
	var keyImported bool
	if err == nil && publicKey != "" {
		if importErr := ImportKeyDirectly(publicKey); importErr == nil {
			keyImported = true
			fmt.Printf("[DEBUG][PGP] imported key from signature block (not GitHub)\n")
		} else {
			fmt.Printf("[DEBUG][PGP] failed to import key from signature block: %v\n", importErr)
		}
	}

	// Perform GPG verification
	status, output, verifyErr := performGPGVerification(signature, payload)

	fmt.Printf("[DEBUG][PGP] gpg status=%s verifyErr=%v\n", status, verifyErr)
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines) && i < 8; i++ {
		fmt.Printf("[DEBUG][PGP] gpg: %s\n", lines[i])
	}

	// Check for GitHub automated commits
	if trustpolicies.IsGitHubAutomatedCommit(output, content, nil) {
		return types.GitHubAutomatedSignature, output, verifyErr
	}

	// Additional checks for valid signatures
	if status == types.ValidSignature || status == types.MissingPublicKey {
		if config.Token != "" && config.Repo != "" && sha != "" && keyID != "" {
			fmt.Printf("[DEBUG][PGP] calling ValidateAuthorization(keyID=%s repo=%s sha=%s)\n", keyID, config.Repo, sha)
			authStatus, authMessage, authErr := ValidateAuthorization(keyID, config.Repo, sha, config.Token)
			fmt.Printf("[DEBUG][PGP] ValidateAuthorization -> status=%s err=%v msg=%q\n", authStatus, authErr, authMessage)

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
