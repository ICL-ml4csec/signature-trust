package gpg

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
)

// ExtractPublicKeyFromSignature extracts GPG public key and key ID from signature
func ExtractPublicKeyFromSignature(signature string) (publicKey string, keyID string, err error) {
	cmd := exec.Command("gpg", "--list-packets")
	cmd.Stdin = strings.NewReader(signature)
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
		return "", "", fmt.Errorf("could not extract key ID from signature")
	}

	publicKey, err = FetchKeyFromKeyserver(keyID)
	if err != nil {
		return "", keyID, fmt.Errorf("could not fetch key %s from keyservers: %v", keyID, err)
	}

	return publicKey, keyID, nil
}

// ExtractSignatureFromCommit extracts PGP signature from commit content
func ExtractSignatureFromCommit(content string) (signature string, payload string, found bool) {
	if !strings.Contains(content, "gpgsig -----BEGIN PGP SIGNATURE-----") {
		return "", "", false
	}

	lines := strings.Split(content, "\n")
	sigStart := -1
	sigEnd := -1

	// Find signature boundaries
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

	// Extract signature lines
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

	// Extract payload (everything except signature)
	var payloadLines []string
	for i, line := range lines {
		if i < sigStart || i > sigEnd {
			payloadLines = append(payloadLines, line)
		}
	}

	// Remove trailing empty lines from payload
	for len(payloadLines) > 0 && payloadLines[len(payloadLines)-1] == "" {
		payloadLines = payloadLines[:len(payloadLines)-1]
	}

	payload = strings.Join(payloadLines, "\n") + "\n"

	return signature, payload, true
}

// ClassifySignature determines the status of a GPG signature from verification output
func ClassifySignature(output string) types.SignatureStatus {
	lowerOutput := strings.ToLower(output)

	switch {
	// Expired but valid
	case strings.Contains(lowerOutput, "good") &&
		(strings.Contains(lowerOutput, "expired") || strings.Contains(lowerOutput, "key expired")):
		return types.ValidSignatureButExpiredKey

	// Valid but not certified/trusted
	case strings.Contains(lowerOutput, "good") &&
		(strings.Contains(lowerOutput, "no indication") ||
			strings.Contains(lowerOutput, "not certified")):
		return types.ValidSignatureButSignerNotCertified

	// Good signatures (any type)
	case strings.Contains(lowerOutput, "good signature"):
		return types.ValidSignature

	// Missing keys (various formats)
	case strings.Contains(lowerOutput, "no public key") ||
		strings.Contains(lowerOutput, "public key not found") ||
		strings.Contains(lowerOutput, "can't check signature: no public key"):
		return types.MissingPublicKey

	// Bad/invalid signatures
	case strings.Contains(lowerOutput, "bad signature") ||
		strings.Contains(lowerOutput, "signature verification failed") ||
		strings.Contains(lowerOutput, "invalid signature"):
		return types.InvalidSignature

	// GPG errors and failures
	case strings.Contains(lowerOutput, "gpg: fatal") ||
		strings.Contains(lowerOutput, "gpg: error") ||
		strings.Contains(lowerOutput, "verification failed") ||
		strings.Contains(lowerOutput, "exit status"):
		return types.VerificationError

	// No signature
	default:
		return types.UnsignedCommit
	}
}
