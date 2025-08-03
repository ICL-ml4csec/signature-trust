package ssh

import (
	"fmt"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/github"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
)

// ValidateAuthorization checks if SSH key belongs to the commit author on GitHub
func ValidateAuthorization(pubKeyBlob []byte, repo, commitSHA, token string) (bool, error) {
	if token == "" {
		return true, fmt.Errorf("no GitHub token provided")
	}

	fingerprint, err := utils.ComputeFingerprintFlexible(pubKeyBlob)
	if err != nil {
		return false, fmt.Errorf("failed to compute fingerprint: %v", err)
	}

	username, err := github.GetCommitContributor(repo, commitSHA, token)
	if err != nil {
		return false, fmt.Errorf("failed to get commit contributor: %v", err)
	}

	keys, err := github.GetUserSSHSigningKeys(username, token)
	if err != nil {
		return false, fmt.Errorf("failed to get user SSH signing keys: %v", err)
	}

	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			return true, nil
		}
	}

	return false, nil
}
