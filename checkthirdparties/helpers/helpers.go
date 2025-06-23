package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
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

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
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

func CleanVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimLeft(version, "^~>=< ")
	return version
}

func semverLess(a, b string) bool {
	as := parseSemverParts(a)
	bs := parseSemverParts(b)
	for i := 0; i < 3; i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return false
}

func parseSemverParts(version string) [3]int {
	parts := strings.Split(version, ".")
	var res [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		res[i] = n
	}
	return res
}

func ResolveVersion(requested string, versions map[string]interface{}) string {
	requested = strings.TrimSpace(requested)

	var versionList []string
	for v := range versions {
		versionList = append(versionList, v)
	}

	sort.Slice(versionList, func(i, j int) bool {
		return semverLess(versionList[i], versionList[j])
	})

	if requested == "" || requested == "*" || strings.ToLower(requested) == "latest" {
		return versionList[len(versionList)-1]
	}

	if strings.Contains(requested, " - ") {
		parts := strings.Split(requested, " - ")
		if len(parts) == 2 {
			min := strings.TrimSpace(parts[0])
			max := strings.TrimSpace(parts[1])
			for i := len(versionList) - 1; i >= 0; i-- {
				if !semverLess(versionList[i], min) && !semverLess(max, versionList[i]) {
					return versionList[i]
				}
			}
		}
	}

	if strings.HasSuffix(requested, ".x") {
		prefix := strings.TrimSuffix(requested, ".x")
		if !strings.HasSuffix(prefix, ".") {
			prefix += "."
		}
		for i := len(versionList) - 1; i >= 0; i-- {
			if strings.HasPrefix(versionList[i], prefix) {
				return versionList[i]
			}
		}
	}

	switch {
	case strings.HasPrefix(requested, ">="):
		bound := strings.TrimPrefix(requested, ">=")
		for i := len(versionList) - 1; i >= 0; i-- {
			if !semverLess(versionList[i], bound) {
				return versionList[i]
			}
		}
	case strings.HasPrefix(requested, ">"):
		bound := strings.TrimPrefix(requested, ">")
		for i := len(versionList) - 1; i >= 0; i-- {
			if semverLess(bound, versionList[i]) {
				return versionList[i]
			}
		}
	case strings.HasPrefix(requested, "<="):
		bound := strings.TrimPrefix(requested, "<=")
		for i := len(versionList) - 1; i >= 0; i-- {
			if !semverLess(bound, versionList[i]) {
				return versionList[i]
			}
		}
	case strings.HasPrefix(requested, "<"):
		bound := strings.TrimPrefix(requested, "<")
		for i := len(versionList) - 1; i >= 0; i-- {
			if semverLess(versionList[i], bound) {
				return versionList[i]
			}
		}
	}

	if strings.HasPrefix(requested, "^") {
		base := parseSemverParts(strings.TrimPrefix(requested, "^"))
		for i := len(versionList) - 1; i >= 0; i-- {
			vParts := parseSemverParts(versionList[i])
			if vParts[0] == base[0] && !semverLess(versionList[i], strings.TrimPrefix(requested, "^")) {
				return versionList[i]
			}
		}
	}

	if strings.HasPrefix(requested, "~") {
		base := parseSemverParts(strings.TrimPrefix(requested, "~"))
		for i := len(versionList) - 1; i >= 0; i-- {
			vParts := parseSemverParts(versionList[i])
			if vParts[0] == base[0] && vParts[1] == base[1] && !semverLess(versionList[i], strings.TrimPrefix(requested, "~")) {
				return versionList[i]
			}
		}
	}

	for _, v := range versionList {
		if v == requested {
			return v
		}
	}

	return ""
}
