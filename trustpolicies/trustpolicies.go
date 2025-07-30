package trustpolicies

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
)

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
