package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hannajonsd/git-signature-test/client"
)

type GitHubTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

func GetSHAFromTag(repoURL string, version string, token string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/tags", repoURL)
	resp, err := client.DoGet(url, token)
	if resp.StatusCode != 200 {
		fmt.Printf("GitHub API returned HTTP %d for repo %s\n", resp.StatusCode, repoURL)
	}
	if err != nil {
		return "", fmt.Errorf("error fetching tags: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", fmt.Errorf("error reading tags response: %v", err)
	}

	var tags []GitHubTag
	err = json.Unmarshal(body, &tags)

	if err != nil {
		return "", fmt.Errorf("error parsing tags JSON: %v", err)
	}

	candidates := []string{version, "v" + version}
	for _, candidate := range candidates {
		for _, tag := range tags {
			if tag.Name == candidate {
				return tag.Commit.SHA, nil
			}
		}
	}

	return "", fmt.Errorf("no matching tag found for version %s", version)
}

func CleanGitHubURL(url string) string {
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.Replace(url, "github.com/", "", 1)
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")
	return url
}
