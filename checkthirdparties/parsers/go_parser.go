package parsers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hannajonsd/git-signature-test/checksignature"
	"github.com/hannajonsd/git-signature-test/checkthirdparties/helpers"
)

func parseGoDependencyLine(line string, token string) {
	if !strings.HasPrefix(line, "github.com/") {
		return
	}
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return
	}
	repo := strings.TrimPrefix(parts[0], "github.com/")
	version := parts[1]

	fmt.Printf("\nManifest: go.mod\n")
	fmt.Printf("Package: %s Version: %s\n", repo, version)
	fmt.Printf("Repository URL: %s\n", repo)

	sha, err := helpers.GetSHAFromTag(repo, version, token)
	if err != nil {
		fmt.Printf("Error getting SHA for %s@%s: %v\n", repo, version, err)
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
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
