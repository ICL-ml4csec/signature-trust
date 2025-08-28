package gpg

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/ICL-ml4csec/signature-trust/checksignature/types"
)

// ExtractPublicKeyFromSignature extracts a GPG public key and its key ID from a given ASCII-armored signature.
// It uses `gpg --list-packets` to parse the signature, then attempts to fetch the key from known keyservers.
func ExtractPublicKeyFromSignature(signature string) (publicKey string, keyID string, err error) {
	cmd := exec.Command("gpg", "--list-packets")
	cmd.Stdin = strings.NewReader(signature)

	// Parse the signature to extract key ID
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to parse PGP signature: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "keyid") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "keyid" && i+1 < len(parts) {
					keyID = parts[i+1]
					break
				}
			}
		}
	}

	if keyID == "" {
		// Parsing failed or key ID not found in expected format
		return "", "", fmt.Errorf("could not extract key ID from signature")
	}

	publicKey, err = FetchKeyFromKeyserver(keyID)
	if err != nil {
		return "", keyID, fmt.Errorf("could not fetch key %s from keyservers: %v", keyID, err)
	}

	return publicKey, keyID, nil
}

// ExtractSignatureFromCommit extracts the GPG signature and signed payload from the raw commit content.
func ExtractSignatureFromCommit(content string) (signature string, payload string, found bool) {
	if !strings.Contains(content, "gpgsig -----BEGIN PGP SIGNATURE-----") {
		return "", "", false
	}

	lines := strings.Split(content, "\n")
	sigStart := -1
	sigEnd := -1

	// Find signature boundaries in commit content
	for i, line := range lines {
		if strings.HasPrefix(line, "gpgsig -----BEGIN PGP SIGNATURE-----") {
			sigStart = i
		}
		if strings.HasPrefix(line, " -----END PGP SIGNATURE-----") {
			sigEnd = i
			break
		}
	}

	if sigStart == -1 || sigEnd == -1 {
		return "", "", false
	}

	// Extract signature lines, handling multiline format with "gpgsig " and continuation lines
	var sigLines []string
	for i := sigStart; i <= sigEnd; i++ {
		line := lines[i]
		if strings.HasPrefix(line, "gpgsig ") {
			sigContent := strings.TrimPrefix(line, "gpgsig ")
			sigLines = append(sigLines, sigContent)
		} else if strings.HasPrefix(line, " ") {
			sigContent := strings.TrimPrefix(line, " ")
			sigLines = append(sigLines, sigContent)
		}
	}
	signature = strings.Join(sigLines, "\n")

	// Extract payload: all content outside the signature block
	var payloadLines []string
	for i, line := range lines {
		if i < sigStart || i > sigEnd {
			payloadLines = append(payloadLines, line)
		}
	}

	// Ensure payload ends with newline
	for len(payloadLines) > 0 && payloadLines[len(payloadLines)-1] == "" {
		payloadLines = payloadLines[:len(payloadLines)-1]
	}
	payload = strings.Join(payloadLines, "\n") + "\n"

	return signature, payload, true
}

// ClassifySignature determines the signature status based on GPG output.
// It returns enums for valid, expired, untrusted, missing, or invalid signatures,
// and treats revoked keys as a type of expired key.
func ClassifySignature(output string) types.SignatureStatus {
	lowerOutput := strings.ToLower(output)

	// Handle valid signatures with expired keys
	if strings.Contains(lowerOutput, "good") &&
		(strings.Contains(lowerOutput, "expired") ||
			strings.Contains(lowerOutput, "key expired") ||
			strings.Contains(lowerOutput, "revoked")) {
		return types.ValidSignatureButExpiredKey
	}

	// Handle valid signatures with untrusted or uncertified keys
	if strings.Contains(lowerOutput, "good") &&
		(strings.Contains(lowerOutput, "no indication") ||
			strings.Contains(lowerOutput, "not certified")) {
		return types.ValidSignatureButSignerNotCertified
	}

	// Handle valid signatures
	if strings.Contains(lowerOutput, "good signature") {
		return types.ValidSignature
	}

	// Handle missing keys
	if strings.Contains(lowerOutput, "no public key") ||
		strings.Contains(lowerOutput, "public key not found") ||
		strings.Contains(lowerOutput, "can't check signature: no public key") {
		return types.MissingPublicKey
	}

	// Handle invalid or corrupted signatures
	if strings.Contains(lowerOutput, "bad signature") ||
		strings.Contains(lowerOutput, "signature verification failed") ||
		strings.Contains(lowerOutput, "invalid signature") {
		return types.InvalidSignature
	}

	// Handle GPG internal errors
	if strings.Contains(lowerOutput, "gpg: fatal") ||
		strings.Contains(lowerOutput, "gpg: error") ||
		strings.Contains(lowerOutput, "verification failed") ||
		strings.Contains(lowerOutput, "exit status") {
		return types.VerificationError
	}

	// No signature found
	return types.UnsignedCommit
}
