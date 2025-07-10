package checksignature

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ICL-ml4sec/msc-hmj24/client"
)

type SignatureStatus string

const (
	ValidSignature                SignatureStatus = "valid"
	ExpiredButValidSignature      SignatureStatus = "valid-but-expired-key"
	InvalidSignature              SignatureStatus = "invalid"
	MissingPublicKey              SignatureStatus = "signed-but-missing-key"
	ValidSignatureButNotCertified SignatureStatus = "valid-but-not-certified"
	UnsignedCommit                SignatureStatus = "unsigned"
	VerificationError             SignatureStatus = "error"
)

type SignatureCheckResult struct {
	CommitSHA string
	Status    string
	Output    string
	Err       error
}

func extractKeyID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "using RSA key") {
			parts := strings.Fields(line)
			return parts[len(parts)-1]
		}
	}
	return ""
}

func importGPGKeyFromGitHub(username string, token string) error {
	url := fmt.Sprintf("https://github.com/%s.gpg", username)
	resp, err := client.DoGet(url, token)

	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub GPG key not found for user %s (status: %d)", username, resp.StatusCode)
	}

	if err != nil {
		return fmt.Errorf("HTTP error fetching GitHub GPG key: %v", err)
	}
	defer resp.Body.Close()

	cmd := exec.Command("gpg", "--import")
	cmd.Stdin = resp.Body
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to import GitHub GPG key for %s: %v\nOutput:\n%s", username, err, string(out))
	}

	fmt.Printf("Successfully imported GPG key(s) from https://github.com/%s.gpg\n", username)
	return nil
}

func classifySignature(output string) SignatureStatus {
	switch {
	case strings.Contains(output, "Good signature") &&
		strings.Contains(output, "expired"):
		return ExpiredButValidSignature

	case strings.Contains(output, "Good signature") &&
		strings.Contains(output, "There is no indication that the signature belongs to the owner"):
		return ValidSignatureButNotCertified

	case strings.Contains(output, "Good signature"):
		return ValidSignature

	case strings.Contains(output, "Can't check signature: No public key"):
		return MissingPublicKey

	case strings.Contains(output, "BAD signature") ||
		strings.Contains(output, "Can't check signature"):
		return InvalidSignature

	default:
		return UnsignedCommit
	}
}

func CheckSignatureLocal(repoPath, sha string, token string) ([]SignatureCheckResult, error) {
	githubUsername := strings.Split(repoPath, "/")[0]

	repoURL := fmt.Sprintf("https://github.com/%s.git", repoPath)
	tmpDir, err := os.MkdirTemp("", "repo-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if out, err := exec.Command("git", "clone", repoURL, tmpDir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to clone: %v\n%s", err, out)
	}

	cmd := exec.Command("git", "rev-list", "-n", "10", sha) // make configurable
	cmd.Dir = tmpDir
	shaListRaw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list commits: %v", err)
	}
	shas := strings.Split(strings.TrimSpace(string(shaListRaw)), "\n")

	var results []SignatureCheckResult
	attemptedKeys := make(map[string]bool)

	for _, s := range shas {
		verify := exec.Command("git", "verify-commit", s)
		verify.Dir = tmpDir
		outputBytes, err := verify.CombinedOutput()
		output := string(outputBytes)

		status := classifySignature(output)

		if status == MissingPublicKey {
			keyID := extractKeyID(output)

			if keyID != "" && !attemptedKeys[keyID] {
				fmt.Printf("Missing key %s. Attempting to fetch...\n", keyID)

				if err := importGPGKeyFromGitHub(githubUsername, token); err != nil {
					fmt.Printf("Failed to import key %s: %v\n", keyID, err)
				}

				attemptedKeys[keyID] = true
			}
		}

		results = append(results, SignatureCheckResult{
			CommitSHA: s,
			Status:    string(status),
			Output:    output,
			Err:       err,
		})
	}

	return results, nil
}
