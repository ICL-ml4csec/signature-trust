package trustpolicies

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ICL-ml4csec/signature-trust/checksignature/github"
	"github.com/ICL-ml4csec/signature-trust/checksignature/types"
	"github.com/ICL-ml4csec/signature-trust/checksignature/utils"
	"github.com/ICL-ml4csec/signature-trust/checkthirdparties/helpers"
)

// GetPGPKeyCreationTime retrieves the creation time of a PGP key by its ID
func GetPGPKeyCreationTime(keyID string) (time.Time, error) {
	cmd := exec.Command("gpg", "--with-colons", "--list-keys", keyID)
	output, err := cmd.Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to list key %s: %v", keyID, err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "pub:") {
			fields := strings.Split(line, ":")
			if len(fields) > 5 {
				epochStr := fields[5]
				epoch, err := strconv.ParseInt(epochStr, 10, 64)
				if err != nil {
					return time.Time{}, fmt.Errorf("invalid epoch in key info: %v", err)
				}
				return time.Unix(epoch, 0), nil
			}
		}
	}

	return time.Time{}, fmt.Errorf("creation time not found for key %s", keyID)
}

// GetSSHKeyCreationTime validates SSH key age against GitHub registration and cutoff date
func GetSSHKeyCreationTime(pubKeyBlob []byte, repo, commitSHA, token string, cutoff *time.Time) (bool, *time.Time, error) {
	fingerprint, err := utils.ComputeFingerprintFlexible(pubKeyBlob)
	if err != nil {
		return false, nil, err
	}

	username, err := github.GetCommitContributor(repo, commitSHA, token)
	if err != nil {
		return false, nil, err
	}

	keys, err := github.GetUserSSHSigningKeys(username, token)
	if err != nil {
		return false, nil, err
	}

	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			if cutoff != nil && key.CreatedAt.After(*cutoff) {
				return false, &key.CreatedAt, nil
			}
			return true, &key.CreatedAt, nil
		}
	}

	return false, nil, fmt.Errorf("key fingerprint not found in GitHub account")
}

var githubGPGKeyIDs = map[string]bool{
	"B5690EEEBB952194": true,
	"4AEE18F83AFDEB23": true,
}

// IsGitHubAutomatedCommit checks if a commit is from GitHub's automated systems
func IsGitHubAutomatedCommit(gpgOutput string, content string, sshSig *types.SSHSignatureData) bool {
	// Check author email patterns
	authorEmail := utils.ExtractAuthorEmail(content)
	if authorEmail == "noreply@github.com" ||
		strings.HasSuffix(authorEmail, "@users.noreply.github.com") {
		return true
	}

	// Check GPG output for GitHub patterns
	if gpgOutput != "" {
		// Check for GitHub email in signature
		if strings.Contains(gpgOutput, "noreply@github.com") ||
			strings.Contains(gpgOutput, "GitHub <noreply@github.com>") {
			return true
		}

		// Check for known GitHub GPG key IDs
		keyID := ExtractKeyIDFromGPGOutput(gpgOutput)
		if keyID != "" {
			normalizedKeyID := utils.NormalizeKeyID(keyID)
			if githubGPGKeyIDs[normalizedKeyID] {
				return true
			}
		}

		// Check for GitHub's signature patterns in output
		if strings.Contains(gpgOutput, "GitHub's verified signature") ||
			strings.Contains(gpgOutput, "created on GitHub.com") {
			return true
		}
	}

	// Check SSH signature
	if sshSig != nil {
		if sshSig.IdentityComment == "noreply@github.com" ||
			strings.HasSuffix(sshSig.IdentityComment, "@users.noreply.github.com") {
			return true
		}
	}

	return false
}

// extractKeyIDFromGPGOutput extracts the GPG key ID from GPG verification output
func ExtractKeyIDFromGPGOutput(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "using") && strings.Contains(line, "key") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "key" && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}

		if strings.Contains(line, "signature from") && strings.Contains(line, "key ID") {
			if idx := strings.Index(line, "key ID "); idx != -1 {
				keyPart := line[idx+7:]
				parts := strings.Fields(keyPart)
				if len(parts) > 0 {
					return parts[0]
				}
			}
		}
	}
	return ""
}

func GetSHAFromTime(repoDir, branch string, cutoff time.Time) (string, error) {
	checkBranchCmd := exec.Command("git", "rev-parse", "--verify", "origin/"+branch)
	checkBranchCmd.Dir = repoDir
	if err := checkBranchCmd.Run(); err != nil {
		branch = helpers.GetDefaultBranch(repoDir)
	}

	ts := fmt.Sprintf("%d", cutoff.Unix())

	cmd := exec.Command("git", "rev-list", "-1", "--before="+ts, "origin/"+branch)
	cmd.Dir = repoDir
	out, err := cmd.Output()

	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 128 {
		fmt.Printf("No commits older than %s on branch %s in %s - falling back to checking all commits\n",
			cutoff.Format(time.RFC3339), branch, repoDir)
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("git rev-list: %w", err)
	}

	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return "", nil
	}
	return sha, nil
}
