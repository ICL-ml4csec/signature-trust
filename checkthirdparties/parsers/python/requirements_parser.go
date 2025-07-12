package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ICL-ml4sec/msc-hmj24/checksignature"
	"github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/helpers"
	"github.com/ICL-ml4sec/msc-hmj24/client"
)

type pypiResponse struct {
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

func extractRepoURLFromPyPI(pypiResp pypiResponse) string {
	if url, ok := pypiResp.Info.ProjectURLs["Homepage"]; ok && url != "" {
		return url
	}
	if url, ok := pypiResp.Info.ProjectURLs["Source"]; ok && url != "" {
		return url
	}
	if url, ok := pypiResp.Info.ProjectURLs["Repository"]; ok && url != "" {
		return url
	}
	if pypiResp.Info.HomePage != "" {
		return pypiResp.Info.HomePage
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

		resp, err := client.DoGet(pypiURL, token)
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

		var pypiResp pypiResponse
		if err := json.Unmarshal(body, &pypiResp); err != nil {
			fmt.Printf("Error parsing PyPI JSON: %v\n", err)
			continue
		}

		if version == "" {
			version = pypiResp.Info.Version
			fmt.Printf("No version specified. Using latest from PyPI: %s\n", version)
		}

		repoURL := extractRepoURLFromPyPI(pypiResp)
		if repoURL == "" {
			fmt.Printf("No repository URL found for %v\n", packageName)
			continue
		}

		normalisedRepo := helpers.CleanGitHubURL(repoURL)

		fmt.Printf("Manifest: requirements.txt\n")
		fmt.Printf("Package: %s Version: %s\n", packageName, version)
		fmt.Printf("Repository URL: %s\n", normalisedRepo)

		sha, err := helpers.GetSHAFromTag(normalisedRepo, version, token)
		if err != nil {
			fmt.Printf("Error getting SHA for %s@%s: %v\n\n", packageName, version, err)
			continue
		}

		commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=10", normalisedRepo, sha)
		checksignature.CheckSignature(commitsURL, token)

		// results, err := checksignature.CheckSignatureLocal(normalisedRepo, sha, token)
		// if err != nil {
		// 	fmt.Println("Error checking signatures locally:", err)
		// 	continue
		// }
		// helpers.PrintSignatureResults(results, "Local")

	}
	return nil
}
