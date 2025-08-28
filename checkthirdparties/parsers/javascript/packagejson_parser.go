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

type PackageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type NpmPackageResponse struct {
	Repository struct {
		URL string `json:"url"`
	} `json:"repository"`
	Versions map[string]interface{} `json:"versions"`
	DistTags map[string]string      `json:"dist-tags"`
}

// extractRepoURLFromNpm extracts the repository URL from the NPM package response
func extractRepoURLFromNpm(npmResp NpmPackageResponse) string {
	repoURL := npmResp.Repository.URL
	if repoURL == "" {
		return ""
	}
	return repoURL
}

// ParsePackageJSON parses package.json and returns structured dependency results
func ParsePackageJSON(file string, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) ([]output.DependencyReport, error) {
	var results []output.DependencyReport
	var packageJSON PackageJSON

	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, fmt.Errorf("error parsing package.json: %v", err)
	}

	processDeps := func(depType string, deps map[string]string) {
		for pkg, version := range deps {
			depResult := processJSDependency(pkg, version, depType, token, config, timeCutoff, outputFormat)
			if depResult != nil {
				results = append(results, *depResult)
			}
		}
	}

	processDeps("dependencies", packageJSON.Dependencies)
	processDeps("devDependencies", packageJSON.DevDependencies)

	return results, nil
}

// processJSDependency processes a single JavaScript dependency and returns a DependencyReport
func processJSDependency(pkg, version, source, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) *output.DependencyReport {
	if helpers.IsTarballURL(version) || helpers.IsLocalPath(version) {
		fmt.Printf("[WARN] Resolution not implemented for tarballs or local paths: %q (%q)\n", pkg, version)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  version,
			Manifest: "package.json",
			Source:   source,
			Status:   "SKIPPED",
			Issues:   []string{"Tarball or local path not supported"},
		}
	}

	normalizedName, kind, cleanVersion := helpers.NormalizeDependencyName(pkg, version)

	switch kind {
	case "git":
		return processGitDependency(pkg, normalizedName, cleanVersion, token, config, timeCutoff, outputFormat)
	case "github-shorthand":
		return processGitHubShorthand(pkg, normalizedName, cleanVersion, token, config, timeCutoff, outputFormat)
	default:
		return processNpmDependency(pkg, normalizedName, version, cleanVersion, token, config, timeCutoff, outputFormat)
	}
}

// processGitDependency processes a Git dependency and returns a DependencyReport
func processGitDependency(pkg, normalizedName, cleanVersion, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) *output.DependencyReport {
	fmt.Printf("[INFO] Git dependency for %q: %q\n", normalizedName, cleanVersion)
	tag := helpers.ExtractGitTag(cleanVersion)
	if tag == "" {
		fmt.Printf("[WARN] No tag found in Git URL for %q\n", normalizedName)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  cleanVersion,
			Manifest: "package.json",
			Status:   "ERROR",
			Issues:   []string{"No tag found in Git URL"},
		}
	}

	baseURL := strings.Split(cleanVersion, "#")[0]
	repoInfo, err := helpers.ExtractRepoInfo(baseURL)
	if err != nil {
		fmt.Printf("[WARN] Invalid Git repository URL for %q: %v\n", normalizedName, err)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  cleanVersion,
			Manifest: "package.json",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("Invalid repository format: %v", err)},
		}
	}

	return parsers.CheckSignaturesAndBuildReport(repoInfo, pkg, tag, token, config, timeCutoff, outputFormat, "package.json")
}

// processGitHubShorthand processes a GitHub shorthand dependency and returns a DependencyReport
func processGitHubShorthand(pkg, normalizedName, cleanVersion, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) *output.DependencyReport {
	fmt.Printf("[INFO] GitHub shorthand for %q: %q\n", normalizedName, cleanVersion)
	gitURL := helpers.ExpandGitHubShorthand(cleanVersion)

	repoInfo, err := helpers.ExtractRepoInfo(gitURL)
	if err != nil {
		fmt.Printf("[WARN] Invalid GitHub shorthand URL for %q: %v\n", normalizedName, err)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  cleanVersion,
			Manifest: "package.json",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("Invalid GitHub shorthand format: %v", err)},
		}
	}

	tag := helpers.ExtractGitTag(cleanVersion)
	if tag == "" {
		tag = "latest"
	}

	return parsers.CheckSignaturesAndBuildReport(repoInfo, pkg, tag, token, config, timeCutoff, outputFormat, "package.json")
}

// processNpmDependency processes an NPM dependency and returns a DependencyReport
func processNpmDependency(pkg, normalizedName, version, cleanVersion, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) *output.DependencyReport {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", normalizedName)
	resp, err := client.DoGet(url, token)
	if err != nil {
		fmt.Printf("[NPM] Fetch failed for %s: %v\n", normalizedName, err)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  version,
			Manifest: "package.json",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("NPM fetch failed: %v", err)},
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var npmResp NpmPackageResponse
	if err := json.Unmarshal(body, &npmResp); err != nil {
		fmt.Printf("[NPM] Error parsing NPM JSON for %s: %v\n", normalizedName, err)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  version,
			Manifest: "package.json",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("NPM JSON parse failed: %v", err)},
		}
	}

	// Resolve version
	resolved := helpers.ResolveVersion(cleanVersion, npmResp.Versions)
	if resolved == "" {
		if latest, ok := npmResp.DistTags["latest"]; ok {
			resolved = latest
		} else {
			return &output.DependencyReport{
				Package:  pkg,
				Version:  version,
				Manifest: "package.json",
				Status:   "ERROR",
				Issues:   []string{"No version resolved"},
			}
		}
	}

	repoURL := extractRepoURLFromNpm(npmResp)
	if repoURL == "" {
		fmt.Printf("[WARN] No repository URL found for %q (%q)\n", pkg, version)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  resolved,
			Manifest: "package.json",
			Status:   "SKIPPED",
			Issues:   []string{"No repository URL found"},
		}
	}

	repoInfo, err := helpers.ExtractRepoInfo(repoURL)
	if err != nil {
		fmt.Printf("[WARN] Invalid repository URL for %q (%q): %v\n", pkg, version, err)
		return &output.DependencyReport{
			Package:  pkg,
			Version:  resolved,
			Manifest: "package.json",
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("Invalid repository format: %v", err)},
		}
	}

	config.Repo = repoInfo.FullName

	return parsers.CheckSignaturesAndBuildReport(repoInfo, pkg, resolved, token, config, timeCutoff, outputFormat, "package.json")
}
