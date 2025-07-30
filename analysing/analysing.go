package analysing

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature"
	"github.com/ICL-ml4csec/msc-hmj24/client"
)

type KeyAnalysisResult struct {
	Username        string
	KeyCount        int
	RecentKeys      []GitHubUserKey
	OldKeys         []GitHubUserKey
	TotalSuspicious int
}

type GitHubUserKey struct {
	ID          int       `json:"id"`
	Key         string    `json:"key"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
	Title       string    `json:"title"`
}

func GetSignedCommits(results []checksignature.SignatureCheckResult) []checksignature.SignatureCheckResult {
	var signedCommits []checksignature.SignatureCheckResult
	for _, result := range results {
		switch result.Status {
		case string(checksignature.ValidSignature),
			string(checksignature.InvalidSignature),
			string(checksignature.ExpiredButValidSignature),
			string(checksignature.MissingPublicKey),
			string(checksignature.ValidSignatureButNotCertified),
			string(checksignature.GitHubAutomatedSignature):
			signedCommits = append(signedCommits, result)
		}
	}

	return signedCommits
}

func getCommitContributor(repo, commitSHA, token string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, commitSHA)

	resp, err := client.DoGet(url, token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var commit struct {
		Author struct {
			Login string `json:"login"`
		} `json:"author"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&commit); err != nil {
		return "", err
	}

	if commit.Author.Login == "" {
		return "", fmt.Errorf("no GitHub user associated with commit")
	}

	return commit.Author.Login, nil
}

func analyseContributorAllKeys(username, token string, cutoff *time.Time) (KeyAnalysisResult, error) {
	result := KeyAnalysisResult{Username: username}

	var allKeys []GitHubUserKey

	// GPG keys
	if gpgKeys, err := getUserGPGKeys(username, token); err == nil {
		allKeys = append(allKeys, gpgKeys...)
	}

	// SSH authentication keys
	if sshKeys, err := getUserSSHKeys(username, token); err == nil {
		allKeys = append(allKeys, sshKeys...)
	}

	// SSH signing keys
	if sshSigningKeys, err := getUserSSHSigningKeys(username, token); err == nil {
		allKeys = append(allKeys, sshSigningKeys...)
	}

	result.KeyCount = len(allKeys)

	if cutoff != nil {
		for _, key := range allKeys {
			if key.CreatedAt.After(*cutoff) {
				result.RecentKeys = append(result.RecentKeys, key)
				result.TotalSuspicious++
			} else {
				result.OldKeys = append(result.OldKeys, key)
			}
		}
	}

	return result, nil
}

func getUserGPGKeys(username, token string) ([]GitHubUserKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/gpg_keys", username)
	return fetchUserKeys(url, token)
}

func getUserSSHKeys(username, token string) ([]GitHubUserKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/keys", username)
	return fetchUserKeys(url, token)
}

func getUserSSHSigningKeys(username, token string) ([]GitHubUserKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/ssh_signing_keys", username)
	return fetchUserKeys(url, token)
}

func fetchUserKeys(url, token string) ([]GitHubUserKey, error) {
	resp, err := client.DoGet(url, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []GitHubUserKey{}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var keys []GitHubUserKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	return keys, nil
}

func getKeyType(keyString string) string {
	if strings.HasPrefix(keyString, "ssh-rsa") {
		return "SSH-RSA"
	} else if strings.HasPrefix(keyString, "ssh-ed25519") {
		return "SSH-Ed25519"
	} else if strings.HasPrefix(keyString, "ecdsa-") {
		return "SSH-ECDSA"
	} else if strings.Contains(keyString, "BEGIN PGP") {
		return "GPG"
	}
	return "Unknown"
}

func AnalyseSignedCommitContributors(repo string, signedCommits []checksignature.SignatureCheckResult, token string, config checksignature.LocalCheckConfig) {
	contributorKeys := make(map[string]KeyAnalysisResult)
	processedContributors := make(map[string]bool)

	fmt.Printf("Checking contributors for each signed commit:\n")

	for i, commit := range signedCommits {
		fmt.Printf("   [%d/%d] Commit %s (%s) - ", i+1, len(signedCommits), commit.CommitSHA[:8], commit.Status)

		contributor, err := getCommitContributor(repo, commit.CommitSHA, token)
		if err != nil {
			fmt.Printf("Could not identify contributor: %v\n", err)
			continue
		}

		fmt.Printf("%s", contributor)

		if processedContributors[contributor] {
			fmt.Printf(" (already analysed)\n")
			continue
		}

		fmt.Printf(" - analysing keys...")
		keyAnalysis, err := analyseContributorAllKeys(contributor, token, config.KeyCreationCutoff)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		contributorKeys[contributor] = keyAnalysis
		processedContributors[contributor] = true

		if keyAnalysis.TotalSuspicious > 0 {
			fmt.Printf("%d recent keys!\n", keyAnalysis.TotalSuspicious)
		} else {
			fmt.Printf("%d keys, all old enough\n", keyAnalysis.KeyCount)
		}
	}

	generateTargetedSecurityReport(repo, signedCommits, contributorKeys, config)
}

func generateTargetedSecurityReport(repo string, signedCommits []checksignature.SignatureCheckResult, contributorKeys map[string]KeyAnalysisResult, config checksignature.LocalCheckConfig) {
	fmt.Printf("\n" + strings.Repeat("-", 60) + "\n")
	fmt.Printf("Contributor analysis: %s\n", repo)
	fmt.Printf(strings.Repeat("-", 60) + "\n")

	totalContributors := len(contributorKeys)
	suspiciousContributors := 0
	totalRecentKeys := 0

	for _, analysis := range contributorKeys {
		if analysis.TotalSuspicious > 0 {
			suspiciousContributors++
			totalRecentKeys += analysis.TotalSuspicious
		}
	}

	fmt.Printf("Analysis Results:\n")
	fmt.Printf("   • Signed commits found: %d\n", len(signedCommits))
	fmt.Printf("   • Unique contributors analysed: %d\n", totalContributors)
	fmt.Printf("   • Contributors with recent keys: %d\n", suspiciousContributors)
	fmt.Printf("   • Total recent keys found: %d\n", totalRecentKeys)

	if config.KeyCreationCutoff != nil {
		fmt.Printf("   • Key age cutoff: %s\n", config.KeyCreationCutoff.Format(time.RFC3339))
	}

	if suspiciousContributors > 0 {
		fmt.Printf("\nContributors with Recent Keys:\n")
		for contributor, analysis := range contributorKeys {
			if analysis.TotalSuspicious > 0 {
				fmt.Printf("   %s: %d recent keys out of %d total\n",
					contributor, analysis.TotalSuspicious, analysis.KeyCount)

				for _, recentKey := range analysis.RecentKeys {
					keyType := getKeyType(recentKey.Key)
					fmt.Printf("      %s key created %s", keyType, recentKey.CreatedAt.Format("2006-01-02"))
					if recentKey.Fingerprint != "" {
						fmt.Printf(" (%s)", recentKey.Fingerprint)
					}
					fmt.Println()
				}
			}
		}
	}

	fmt.Printf(strings.Repeat("-", 60) + "\n")
}
