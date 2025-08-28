package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ICL-ml4csec/signature-trust/client"
)

type GitHubTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

type RepoInfo struct {
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	FullName string `json:"full_name"` // e.g., "owner/repo"
	URL      string `json:"url"`
}

// GetSHAFromTag retrieves the SHA of a specific tag from a GitHub repository
func GetSHAFromTag(repoInfo *RepoInfo, version string, token string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/tags", repoInfo.FullName)
	resp, err := client.DoGet(url, token)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned HTTP %d for repo %s", resp.StatusCode, repoInfo.FullName)
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

// GetSHAFromBranch retrieves the SHA of the latest commit on a specific branch
func GetSHAFromBranch(repo string, branch string, token string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, branch)
	resp, err := client.DoGet(url, token)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned HTTP %d for repo %s", resp.StatusCode, repo)
	}
	if err != nil {
		return "", fmt.Errorf("error fetching branch SHA: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading branch response: %v", err)
	}

	var result struct {
		SHA string `json:"sha"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("error parsing branch JSON: %v", err)
	}

	return result.SHA, nil
}

// ExtractRepoInfo extracts repository information from various URL formats
func ExtractRepoInfo(url string) (*RepoInfo, error) {
	originalURL := url

	// Normalize GitHub URL by removing prefixes, suffixes, and fragments
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

	var majorVersionSuffix = regexp.MustCompile(`/v[0-9]+$`)
	url = majorVersionSuffix.ReplaceAllString(url, "")

	// Validate and split into owner/repo
	parts := strings.Split(url, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid GitHub repository format: %s", originalURL)
	}

	return &RepoInfo{
		Owner:    parts[0],
		Name:     parts[1],
		FullName: url,
		URL:      originalURL,
	}, nil
}

// ExpandGitHubShorthand expands shorthand GitHub URLs to full git+https format
func ExpandGitHubShorthand(input string) string {
	clean := strings.TrimPrefix(input, "github:")
	return "git+https://github.com/" + clean + ".git"
}

// ExtractGitTag extracts the tag from a GitHub URL if present
func ExtractGitTag(url string) string {
	if idx := strings.Index(url, "#"); idx != -1 {
		return url[idx+1:]
	}
	return ""
}

// GetDefaultBranch retrieves the default branch of a GitHub repository
func GetDefaultBranch(repoDir string) string {
	defaultBranchCmd := exec.Command("git", "symbolic-ref", "refs/remotes/origin/HEAD")
	defaultBranchCmd.Dir = repoDir
	defaultBranchOut, err := defaultBranchCmd.Output()
	if err == nil {
		defaultBranchFull := strings.TrimSpace(string(defaultBranchOut))
		return strings.TrimPrefix(defaultBranchFull, "refs/remotes/origin/")
	}

	for _, defaultBranch := range []string{"main", "master"} {
		testCmd := exec.Command("git", "rev-parse", "--verify", "origin/"+defaultBranch)
		testCmd.Dir = repoDir
		if testErr := testCmd.Run(); testErr == nil {
			return defaultBranch
		}
	}

	return "main"
}
