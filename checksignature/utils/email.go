package utils

import (
	"strings"
)

// ExtractSignerEmailFromOutput extracts the email of the signer from GPG verification output
func ExtractSignerEmailFromOutput(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Good signature from") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 && end > start {
				return line[start+1 : end]
			}
		}
	}
	return ""
}

// ExtractAuthorEmail extracts the author email from commit content
func ExtractAuthorEmail(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "author ") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 && end > start {
				return line[start+1 : end]
			}
		}
	}
	return ""
}

// CheckEmailMismatch checks if the signer email matches the commit author email
func CheckEmailMismatch(rawCommit []byte, gpgOutput string) (bool, string, string) {
	signerEmail := ExtractSignerEmailFromOutput(gpgOutput)
	authorEmail := ExtractAuthorEmail(string(rawCommit))

	if signerEmail != "" && authorEmail != "" {
		return signerEmail != authorEmail, signerEmail, authorEmail
	}
	return false, signerEmail, authorEmail
}
