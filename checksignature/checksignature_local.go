package checksignature

import (
	"fmt"
	"io"
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
	EmailNotMatched               SignatureStatus = "signed-but-untrusted-email"
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

func importSSHKeysFromGitHub(username string, token string) (string, error) {
	url := fmt.Sprintf("https://github.com/%s.keys", username)
	resp, err := client.DoGet(url, token)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub SSH keys not found for user %s (status: %d)", username, resp.StatusCode)
	}

	if err != nil {
		return "", fmt.Errorf("HTTP error fetching GitHub SSH keys: %v", err)
	}
	defer resp.Body.Close()

	keys, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read SSH key response: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "allowed_signers_*.txt")
	if err != nil {
		return "", fmt.Errorf("failed to create allowed_signers file: %v", err)
	}
	defer tmpFile.Close()

	lines := strings.Split(string(keys), "\n")
	for _, key := range lines {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		line := fmt.Sprintf("%s %s\n", username, key)
		if _, err := tmpFile.WriteString(line); err != nil {
			return "", fmt.Errorf("failed to write to allowed_signers file: %v", err)
		}
	}

	configCmd := exec.Command("git", "config", "--global", "gpg.ssh.allowedSignersFile", tmpFile.Name())
	if out, err := configCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to set git config: %v\n%s", err, string(out))
	}

	fmt.Printf("Successfully imported SSH key(s) from https://github.com/%s.keys\n", username)
	return tmpFile.Name(), nil
}

func extractEmailsFromSignatureOutput(output string) (signerEmail string, authorEmail string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Good signature from") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 && end > start {
				signerEmail = line[start+1 : end]
			}
		}
		if strings.HasPrefix(line, "Author:") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 && end > start {
				authorEmail = line[start+1 : end]
			}
		}
	}
	return
}

func classifySignature(output string) SignatureStatus {
	signerEmail, authorEmail := extractEmailsFromSignatureOutput(output)

	switch {
	case strings.Contains(output, "Good") && strings.Contains(output, "expired"):
		return ExpiredButValidSignature

	case strings.Contains(output, "Good") &&
		strings.Contains(output, "There is no indication that the signature belongs to the owner"):
		return ValidSignatureButNotCertified

	case strings.Contains(output, "Good") && (strings.Contains(output, "ED25519") || strings.Contains(output, "RSA key")):
		if signerEmail != "" && authorEmail != "" && signerEmail != authorEmail {
			return EmailNotMatched
		}
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

type LocalCheckConfig struct {
	CommitsToCheck         int
	AcceptExpiredKeys      bool
	AcceptUnsignedCommits  bool
	AcceptUntrustedSigners bool
	AcceptUncertifiedKeys  bool
	AcceptMissingPublicKey bool
}

func CheckSignatureLocal(repoPath, sha string, token string, config LocalCheckConfig) ([]SignatureCheckResult, error) {
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

	allowedSignersPath, err := importSSHKeysFromGitHub(githubUsername, token)
	if err != nil {
		fmt.Printf("Failed to import SSH keys for %s: %v\n", githubUsername, err)
	}

	_ = importGPGKeyFromGitHub(githubUsername, token)

	var cmd *exec.Cmd
	if config.CommitsToCheck > 0 {
		cmd = exec.Command("git", "rev-list", "-n", fmt.Sprintf("%d", config.CommitsToCheck), sha)
	} else {
		cmd = exec.Command("git", "rev-list", sha)
	}

	cmd.Dir = tmpDir
	shaListRaw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list commits: %v", err)
	}
	shas := strings.Split(strings.TrimSpace(string(shaListRaw)), "\n")

	var results []SignatureCheckResult
	attemptedKeys := make(map[string]bool)

	for _, s := range shas {
		var output string
		var status SignatureStatus
		var err error

		gpgCmd := exec.Command("git", "log", "-1", "--show-signature", s)
		gpgCmd.Dir = tmpDir
		gpgOut, gpgErr := gpgCmd.CombinedOutput()
		gpgOutput := string(gpgOut)

		status = classifySignature(gpgOutput)
		output = gpgOutput
		err = gpgErr

		if status == MissingPublicKey {
			keyID := extractKeyID(gpgOutput)
			if keyID != "" && !attemptedKeys[keyID] {
				fmt.Printf("Missing GPG key %s. Attempting to fetch...\n", keyID)
				if err := importGPGKeyFromGitHub(githubUsername, token); err != nil {
					fmt.Printf("Failed to import key %s: %v\n", keyID, err)
				}
				attemptedKeys[keyID] = true
			}
		}

		if status == UnsignedCommit || status == MissingPublicKey {
			sshCmd := exec.Command("git", "-c", "gpg.format=ssh",
				"-c", fmt.Sprintf("gpg.ssh.allowedSignersFile=%s", allowedSignersPath),
				"log", "-1", "--show-signature", s)
			sshCmd.Dir = tmpDir
			sshOut, sshErr := sshCmd.CombinedOutput()
			sshOutput := string(sshOut)

			sshStatus := classifySignature(sshOutput)

			if sshStatus != UnsignedCommit && sshStatus != InvalidSignature {
				status = sshStatus
				output = sshOutput
				err = sshErr
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
