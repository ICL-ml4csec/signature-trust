package github

import (
	"encoding/json"
	"fmt"

	"github.com/ICL-ml4csec/signature-trust/client"
)

// GetCommitContributor gets the GitHub username of the commit author
func GetCommitContributor(repo, commitSHA, token string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, commitSHA)

	resp, err := client.DoGet(url, token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	// Minimal struct to extract the GitHub username of the commit author
	var commit struct {
		Author struct {
			Login string `json:"login"`
		} `json:"author"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&commit); err != nil {
		return "", err
	}

	if commit.Author.Login == "" {
		// The commit has no associated GitHub user
		return "", fmt.Errorf("no GitHub user associated with commit")
	}

	return commit.Author.Login, nil
}
