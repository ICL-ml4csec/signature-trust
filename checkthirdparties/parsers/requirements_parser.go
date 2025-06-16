package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/hannajonsd/git-signature-test/checksignature"
	"github.com/hannajonsd/git-signature-test/checkthirdparties/helpers"
)

type PyPIResponse struct {
	Info struct {
		ProjectURLs map[string]string `json:"project_urls"`
		HomePage    string            `json:"home_page"`
		Version     string            `json:"version"`
	} `json:"info"`
	Releases map[string]interface{} `json:"releases"`
}

func parseRequirementLine(line string) (string, string) {
	if strings.Contains(line, "==") {
		parts := strings.SplitN(line, "==", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	if strings.Contains(line, ">=") {
		parts := strings.SplitN(line, ">=", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(line), ""
}

func extractRepoURL(pypiresp PyPIResponse) string {
	if url, ok := pypiresp.Info.ProjectURLs["Homepage"]; ok && url != "" {
		return url
	}
	if url, ok := pypiresp.Info.ProjectURLs["Source"]; ok && url != "" {
		return url
	}
	if url, ok := pypiresp.Info.ProjectURLs["Repository"]; ok && url != "" {
		return url
	}
	if pypiresp.Info.HomePage != "" {
		return pypiresp.Info.HomePage
	}
	return ""
}

func ParseRequirements(file string, token string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("error reading requirements.txt: %v", err)
	}

	lines := strings.Split(string(data), "\n")

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		packageName, version := parseRequirementLine(line)
		if packageName == "" {
			fmt.Printf("Skipping invalid line: %v\n", line)
			continue
		}

		pypiURL := fmt.Sprintf("https://pypi.org/pypi/%s/json", packageName)
		fmt.Printf("\nFetching PyPI data for: %s\n", pypiURL)

		resp, err := http.Get(pypiURL)
		if err != nil {
			fmt.Printf("Error fetching PyPI data: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading PyPI response: %v\n", err)
			continue
		}

		var pypiresp PyPIResponse
		if err := json.Unmarshal(body, &pypiresp); err != nil {
			fmt.Printf("Error parsing PyPI JSON: %v\n", err)
			continue
		}

		if version == "" {
			version = pypiresp.Info.Version
			fmt.Printf("No version specified. Using latest from PyPI: %s\n", version)
		}

		repoURL := extractRepoURL(pypiresp)
		if repoURL == "" {
			fmt.Printf("No repository URL found for %v\n", packageName)
			continue
		}

		normalizedRepo := helpers.CleanGitHubURL(repoURL)

		fmt.Printf("Manifest: requirements.txt\n")
		fmt.Printf("Package: %s %s\n", packageName, version)
		fmt.Printf("Repository URL: %s\n", normalizedRepo)

		sha, err := helpers.GetSHAFromTag(normalizedRepo, version, token)
		if err != nil {
			fmt.Printf("%v\n", err)
			continue
		}

		commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=30", normalizedRepo, sha)
		checksignature.CheckSignature(commitsURL, token)
	}
	return nil
}
