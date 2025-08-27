package gpg

import (
	"fmt"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/github"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
)

// CheckKeyAuthorization verifies if a GPG key is registered on the commit author's GitHub account.
// This ensures the signer is actually the expected contributor, not just someone with a valid key.
func CheckKeyAuthorization(keyID, repo, commitSHA, token string) (bool, error) {
	if token == "" {
		// If no GitHub token is provided, skip the authorization check.
		// We return true to avoid failing valid commits, but raise a warning.
		return true, fmt.Errorf("warning: no GitHub token provided, skipping GPG key authorization")
	}

	username, err := github.GetCommitContributor(repo, commitSHA, token)
	if err != nil {
		return false, fmt.Errorf("failed to get commit contributor: %v", err)
	}

	gpgKeys, err := github.GetUserGPGKeys(username, token)
	if err != nil {
		return false, fmt.Errorf("failed to get user GPG keys: %v", err)
	}

	for _, key := range gpgKeys {
		if key.PublicKey != "" {
			if err := ImportKeyDirectly(key.PublicKey); err != nil {
				fmt.Printf("Warning: failed to import key %s from GitHub: %v\n", key.KeyID, err)
			}
		}

		for _, sub := range key.Subkeys {
			if sub.PublicKey != "" {
				if err := ImportKeyDirectly(sub.PublicKey); err != nil {
					fmt.Printf("Warning: failed to import subkey %s: %v\n", sub.KeyID, err)
				}
			}
		}
	}

	// Check if the provided signing key ID matches any registered GPG keys or subkeys
	// on the GitHub account of the commit author.
	for _, key := range gpgKeys {
		// Check primary key
		primaryKeyID := utils.InterfaceToString(key.PrimaryKeyID)
		if utils.NormalizeKeyID(key.KeyID) == utils.NormalizeKeyID(keyID) ||
			utils.NormalizeKeyID(primaryKeyID) == utils.NormalizeKeyID(keyID) {
			return true, nil
		}

		// Subkeys may also be authorized signers if they have signing capability
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

// ValidateAuthorization checks if a GPG signature came from a key that is registered
// on the commit author's GitHub account. This adds an authorization layer on top of cryptographic validation.
func ValidateAuthorization(keyID, repo, commitSHA, token string) (types.SignatureStatus, string, error) {
	authorized, authErr := CheckKeyAuthorization(keyID, repo, commitSHA, token)
	if authErr != nil {
		// If authorization check fails
		// treat signature as valid but return a warning.
		return types.ValidSignature, fmt.Sprintf("Warning: Could not verify GPG key authorization: %v", authErr), nil
	}

	if !authorized {
		// If the key is valid cryptographically but not registered on GitHub,
		// mark it as a valid signature from an unregistered key.
		return types.ValidSignatureButUnregisteredKey,
			fmt.Sprintf("Valid GPG signature with key %s, but key is not registered on the commit author's GitHub account", keyID), nil
	}

	return types.ValidSignature, "", nil
}
