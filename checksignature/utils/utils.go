package utils

import (
	"strings"
)

// RemoveSignatureFromCommit removes the signature block from commit content
func RemoveSignatureFromCommit(raw string) string {
	lines := strings.Split(raw, "\n")
	sigStart := -1
	sigEnd := -1

	// Find signature boundaries
	for i, line := range lines {
		if strings.HasPrefix(line, "gpgsig ") {
			sigStart = i
		}
		if sigStart != -1 && strings.HasPrefix(line, " -----END") {
			sigEnd = i
			break
		}
	}

	if sigStart == -1 || sigEnd == -1 {
		return raw
	}

	// Build result excluding signature lines
	var result []string
	for i, line := range lines {
		if i < sigStart || i > sigEnd {
			result = append(result, line)
		} else {
		}
	}

	final := strings.Join(result, "\n")
	if !strings.HasSuffix(final, "\n") {
		final += "\n"
	}

	return final
}

// NormalizeKeyID normalizes GPG key IDs for comparison
func NormalizeKeyID(keyID string) string {
	keyID = strings.TrimPrefix(keyID, "0x")
	keyID = strings.TrimPrefix(keyID, "0X")
	keyID = strings.ToUpper(keyID)

	if len(keyID) > 16 {
		keyID = keyID[len(keyID)-16:]
	}

	return keyID
}
