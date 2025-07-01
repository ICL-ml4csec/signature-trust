package parsers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hannajonsd/git-signature-test/checksignature"
	"github.com/hannajonsd/git-signature-test/checkthirdparties/helpers"
)

var excludeMap = make(map[string]string)

func parseGoDependencyLine(line string, token string) {
	if idx := strings.Index(line, "//"); idx != -1 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)

	if !strings.HasPrefix(line, "github.com/") {
		fmt.Printf("Skipping non-github dependency (not implemented yet): %s\n\n", line)
		return
	}

	parts := strings.Fields(line)
	if len(parts) != 2 {
		return
	}

	repo := helpers.CleanGitHubURL(parts[0])
	version := parts[1]
	version = strings.Split(version, "+")[0]

	if excludedVersion, ok := excludeMap[repo]; ok && excludedVersion == strings.TrimPrefix(version, "v") {
		fmt.Printf("Excluded: %s@%s (skipped)\n\n", repo, version)
		return
	}

	fmt.Printf("Manifest: go.mod\n")
	fmt.Printf("Package: %s Version: %s\n", repo, version)
	fmt.Printf("Repository URL: %s\n", repo)

	if strings.Contains(version, "-") && strings.HasPrefix(version, "v0.0.0-") {
		fmt.Printf("Pseudo-version detected, falling back to latest semver tag.\n")
		tag, sha, err := helpers.FindLatestSemverTag(repo, token)
		if err != nil {
			fmt.Printf("Error finding latest tag for %s: %v\n\n", repo, err)
			return
		}

		fmt.Printf("Resolved to tag: %s\n", tag)

		if excludedVersion, ok := excludeMap[repo]; ok && excludedVersion == strings.TrimPrefix(tag, "v") {
			fmt.Printf("Excluded after resolving: %s@%s (skipped)\n\n", repo, tag)
			return
		}

		commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=30", repo, sha)
		checksignature.CheckSignature(commitsURL, token)
		return
	}

	sha, err := helpers.GetSHAFromTag(repo, version, token)
	if err != nil {
		fmt.Printf("Error getting SHA for %s@%s: %v\n\n", repo, version, err)
		return
	}

	commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=30", repo, sha)
	checksignature.CheckSignature(commitsURL, token)
}

func ParseGo(file string, token string) error {
	data, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("error opening go.mod: %v", err)
	}
	defer data.Close()

	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "exclude ") {
			line = strings.TrimPrefix(line, "exclude ")
			line = strings.Split(line, "//")[0]
			parts := strings.Fields(line)
			if len(parts) == 2 {
				cleanedRepoPath := helpers.CleanGitHubURL(parts[0])
				version := strings.Split(parts[1], "+")[0]
				version = strings.TrimPrefix(version, "v")
				excludeMap[cleanedRepoPath] = version
				fmt.Printf("Added to excludeMap: %s -> %s\n", cleanedRepoPath, version)
			}
		}
	}

	_, err = data.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("error rewinding go.mod: %v", err)
	}
	scanner = bufio.NewScanner(data)
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "indirect") {
			fmt.Printf("This tool checks only explicitly declared dependencies. Skipping indirect dependency: %s \n\n", line)
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if inRequireBlock || strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			parseGoDependencyLine(line, token)
		}
	}

	return scanner.Err()
}
