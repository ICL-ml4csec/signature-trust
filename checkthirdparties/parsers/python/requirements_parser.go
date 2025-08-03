package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/output"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/parsers"
	"github.com/ICL-ml4csec/msc-hmj24/client"
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

// ParseRequirements parses requirements.txt and returns structured dependency results
func ParseRequirements(file string, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) ([]output.DependencyReport, error) {
	var results []output.DependencyReport

	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading requirements.txt: %v", err)
	}

	lines := strings.Split(string(data), "\n")

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		depResult := processPythonDependency(line, token, config, timeCutoff, outputFormat)
		if depResult != nil {
			results = append(results, *depResult)
		}
	}

	return results, nil
}

func processPythonDependency(line, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) *output.DependencyReport {
	packageName, version := parseRequirementLine(line)
	if packageName == "" {
		fmt.Printf("Skipping invalid line: %v\n", line)
		return nil
	}

	pypiURL := fmt.Sprintf("https://pypi.org/pypi/%s/json", packageName)
	resp, err := client.DoGet(pypiURL, token)
	if err != nil {
		fmt.Printf("Error fetching PyPI data for %s: %v\n", packageName, err)
		return &output.DependencyReport{
			Package:  packageName,
			Version:  version,
			Manifest: "requirements.txt",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("PyPI fetch failed: %v", err)},
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading PyPI response for %s: %v\n", packageName, err)
		return &output.DependencyReport{
			Package:  packageName,
			Version:  version,
			Manifest: "requirements.txt",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("PyPI response read failed: %v", err)},
		}
	}

	var pypiResp pypiResponse
	if err := json.Unmarshal(body, &pypiResp); err != nil {
		fmt.Printf("Error parsing PyPI JSON for %s: %v\n", packageName, err)
		return &output.DependencyReport{
			Package:  packageName,
			Version:  version,
			Manifest: "requirements.txt",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("PyPI JSON parse failed: %v", err)},
		}
	}

	if version == "" {
		version = pypiResp.Info.Version
		fmt.Printf("No version specified for %s. Using latest from PyPI: %s\n", packageName, version)
	}

	repoURL := extractRepoURLFromPyPI(pypiResp)
	if repoURL == "" {
		fmt.Printf("No repository URL found for %s\n", packageName)
		return &output.DependencyReport{
			Package:  packageName,
			Version:  version,
			Manifest: "requirements.txt",
			Status:   "SKIPPED",
			Issues:   []string{"No repository URL found"},
		}
	}

	repoInfo, err := helpers.ExtractRepoInfo(repoURL)
	if err != nil {
		fmt.Printf("Invalid repository URL for %s: %v\n", packageName, err)
		return &output.DependencyReport{
			Package:  packageName,
			Version:  version,
			Manifest: "requirements.txt",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("Invalid repository format: %v", err)},
		}
	}

	return parsers.CheckSignaturesAndBuildReport(repoInfo, packageName, version, token, config, timeCutoff, outputFormat, "requirements.txt")
}
