package gpg

import (
	"fmt"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/github"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
)

// CheckKeyAuthorization verifies if a GPG key is registered on the commit author's GitHub account
func CheckKeyAuthorization(keyID, repo, commitSHA, token string) (bool, error) {
	if token == "" {
		return true, fmt.Errorf("no GitHub token provided, skipping GPG key authorization")
	}

	username, err := github.GetCommitContributor(repo, commitSHA, token)
	if err != nil {
		return false, fmt.Errorf("failed to get commit contributor: %v", err)
	}

	gpgKeys, err := github.GetUserGPGKeys(username, token)
	if err != nil {
		return false, fmt.Errorf("failed to get user GPG keys: %v", err)
	}

	// Check if signing key matches any of their registered keys (including subkeys)
	for _, key := range gpgKeys {
		// Check primary key
		primaryKeyID := utils.InterfaceToString(key.PrimaryKeyID)
		if utils.NormalizeKeyID(key.KeyID) == utils.NormalizeKeyID(keyID) ||
			utils.NormalizeKeyID(primaryKeyID) == utils.NormalizeKeyID(keyID) {
			return true, nil
		}

		// Check subkeys
		for _, subkey := range key.Subkeys {
			subkeyPrimaryID := utils.InterfaceToString(subkey.PrimaryKeyID)
			if subkey.CanSign && (utils.NormalizeKeyID(subkey.KeyID) == utils.NormalizeKeyID(keyID) ||
				utils.NormalizeKeyID(subkeyPrimaryID) == utils.NormalizeKeyID(keyID)) {
				return true, nil
			}
		}
	}

	return false, nil
}

// ValidateAuthorization checks if GPG key belongs to the commit author on GitHub
func ValidateAuthorization(keyID, repo, commitSHA, token string) (types.SignatureStatus, string, error) {
	authorized, authErr := CheckKeyAuthorization(keyID, repo, commitSHA, token)
	if authErr != nil {
		// Log warning but don't fail
		return types.ValidSignature, fmt.Sprintf("Warning: Could not verify GPG key authorization: %v", authErr), nil
	}

	if !authorized {
		return types.ValidSignatureButUnregisteredKey,
			fmt.Sprintf("Valid GPG signature with key %s, but key is not registered on the commit author's GitHub account", keyID), nil
	}

	return types.ValidSignature, "", nil
}
