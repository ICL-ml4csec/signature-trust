package parsers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ICL-ml4sec/msc-hmj24/checksignature"
	"github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/helpers"
)

var excludeMap = make(map[string]string)

type Replacement struct {
	Repo    string
	Version string
}

var replaceMap = make(map[string]Replacement)

func parseGoDependencyLine(line string, token string, config checksignature.LocalCheckConfig) {
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "//") || line == "" {
		return
	}

	if idx := strings.Index(line, "//"); idx != -1 {
		line = line[:idx]
	}

	if !strings.HasPrefix(line, "github.com/") {
		fmt.Printf("Skipping non-github dependency (not implemented yet): %s\n\n", line)
		return
	}

	parts := strings.Fields(line)
	if len(parts) != 2 {
		return
	}

	rawRepo := parts[0]
	cleanedRepo := helpers.CleanGitHubURL(rawRepo)
	version := parts[1]
	version = strings.Split(version, "+")[0]

	if replacement, ok := replaceMap[rawRepo]; ok {
		fmt.Printf("[INFO] Replaced module: %s → %s@%s\n", rawRepo, replacement.Repo, replacement.Version)
		cleanedRepo = helpers.CleanGitHubURL(replacement.Repo)
		version = replacement.Version
	}

	if excludedVersion, ok := excludeMap[cleanedRepo]; ok && excludedVersion == strings.TrimPrefix(version, "v") {
		fmt.Printf("Excluded: %s@%s (skipped)\n\n", cleanedRepo, version)
		return
	}

	fmt.Printf("Manifest: go.mod\n")
	fmt.Printf("Package: %s Version: %s\n", cleanedRepo, version)
	fmt.Printf("Repository URL: %s\n", cleanedRepo)

	if strings.Contains(version, "-") && strings.HasPrefix(version, "v0.0.0-") {
		fmt.Printf("Pseudo-version detected, falling back to latest semver tag.\n")
		tag, sha, err := helpers.FindLatestSemverTag(cleanedRepo, token)
		if err != nil {
			fmt.Printf("Error finding latest tag for %s: %v\n\n", cleanedRepo, err)
			return
		}
		fmt.Printf("Resolved to tag: %s\n", tag)

		if excludedVersion, ok := excludeMap[cleanedRepo]; ok && excludedVersion == strings.TrimPrefix(tag, "v") {
			fmt.Printf("Excluded after resolving: %s@%s (skipped)\n\n", cleanedRepo, tag)
			return
		}

		checksignature.CheckSignature(cleanedRepo, sha, token, config.CommitsToCheck)
		return
	}

	sha, err := helpers.GetSHAFromTag(cleanedRepo, version, token)
	if err != nil {
		fmt.Printf("Error getting SHA for %s@%s: %v\n\n", cleanedRepo, version, err)
		return
	}
	checksignature.CheckSignature(cleanedRepo, sha, token, config.CommitsToCheck)

	results, err := checksignature.CheckSignatureLocal(cleanedRepo, sha, config)
	if err != nil {
		fmt.Println("Error checking signatures locally:", err)
		return
	}
	helpers.PrintSignatureResults(results, "Local", config)
}

func ParseGo(file string, token string, config checksignature.LocalCheckConfig) error {
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
				fmt.Printf("Added to excludeMap: %s -> %s\n\n", cleanedRepoPath, version)
			}
		} else if strings.HasPrefix(line, "replace ") {
			line = strings.TrimPrefix(line, "replace ")
			line = strings.Split(line, "//")[0]
			parts := strings.Fields(line)
			if len(parts) == 4 && parts[1] == "=>" {
				original := parts[0]
				replacement := parts[2]
				version := parts[3]

				if strings.HasPrefix(replacement, "../") || strings.HasPrefix(replacement, "./") {
					fmt.Printf("[SKIP] Replacement points to a local file path, not a GitHub repository: %s => %s (ignored)\n", original, replacement)
					continue
				}

				repo := helpers.CleanGitHubURL(replacement)
				version = strings.Split(version, "+")[0]

				replaceMap[original] = Replacement{Repo: repo, Version: version}
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

		if strings.HasPrefix(line, "//") {
			continue
		}

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
			parseGoDependencyLine(line, token, config)
		}
	}

	return scanner.Err()
}
