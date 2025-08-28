package ssh

import (
	"fmt"

	"github.com/ICL-ml4csec/signature-trust/checksignature/github"
	"github.com/ICL-ml4csec/signature-trust/checksignature/utils"
)

// ValidateAuthorization verifies whether the given SSH public key was registered as a signing key
// for the GitHub user who authored the specified commit.
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
