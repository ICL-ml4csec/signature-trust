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
	repo := CleanGitHubURL(repoURL)
	url := fmt.Sprintf("https://api.github.com/repos/%s/tags", repo)
	resp, err := client.DoGet(url, token)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned HTTP %d for repo %s", resp.StatusCode, repo)
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
	url = strings.Replace(url, "git@github.com:", "", 1)
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "ssh://git@")
	url = strings.Replace(url, "github.com/", "", 1)
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")
	if idx := strings.Index(url, "#"); idx != -1 {
		url = url[:idx]
	}
	return url
}

func ExpandGitHubShorthand(input string) string {
	clean := strings.TrimPrefix(input, "github:")
	return "git+https://github.com/" + clean + ".git"
}

func ExtractGitTag(url string) string {
	if idx := strings.Index(url, "#"); idx != -1 {
		return url[idx+1:]
	}
	return ""
}
