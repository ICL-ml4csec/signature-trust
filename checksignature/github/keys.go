package github

import (
	"encoding/json"
	"fmt"

	"github.com/ICL-ml4csec/signature-trust/checksignature/types"
	"github.com/ICL-ml4csec/signature-trust/checksignature/utils"
	"github.com/ICL-ml4csec/signature-trust/client"
)

// GetUserGPGKeys fetches a user's GPG keys from GitHub
func GetUserGPGKeys(username, token string) ([]types.GitHubGPGKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/gpg_keys", username)

	resp, err := client.DoGet(url, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// No keys found for user – treat as non-error
		return []types.GitHubGPGKey{}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var keys []types.GitHubGPGKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	return keys, nil
}

// GetUserSSHSigningKeys fetches a user's SSH signing keys from GitHub
func GetUserSSHSigningKeys(username, token string) ([]types.GitHubUserKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/ssh_signing_keys", username)
	return fetchUserKeys(url, token)
}

// GetUserSSHKeys fetches a user's SSH authentication keys from GitHub
func GetUserSSHKeys(username, token string) ([]types.GitHubUserKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/keys", username)
	return fetchUserKeys(url, token)
}

// fetchUserKeys is a helper function to fetch different types of user keys
func fetchUserKeys(url, token string) ([]types.GitHubUserKey, error) {
	resp, err := client.DoGet(url, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []types.GitHubUserKey{}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var keys []types.GitHubUserKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	// GitHub sometimes omits the fingerprint field.
	// Compute it manually for consistency in downstream verification.
	for i := range keys {
		if keys[i].Key != "" && keys[i].Fingerprint == "" {
			fingerprint, err := utils.ComputeFingerprintFlexible(keys[i].Key)
			if err != nil {
				// Skip keys we can't fingerprint
				continue
			}
			keys[i].Fingerprint = fingerprint
		}
	}

	return keys, nil
}
