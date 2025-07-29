package trustpolicies

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
)

func KeyCreationTime(keyID string) (int64, error) { // WIP
	return 0, nil
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
