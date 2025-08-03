package parsers

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/output"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
)

var excludeMap = make(map[string]string)

type Replacement struct {
	Repo    string
	Version string
}

var replaceMap = make(map[string]Replacement)

// ParseGoWithResults parses go.mod and returns structured dependency results
func ParseGoWithResults(modFile, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) ([]output.DependencyReport, error) {
	var results []output.DependencyReport

	data, err := os.Open(modFile)
	if err != nil {
		return nil, fmt.Errorf("error opening go.mod: %v", err)
	}
	defer data.Close()

	// First pass: handle exclude and replace directives
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

	// Second pass: process dependencies and collect results
	_, err = data.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("error rewinding go.mod: %v", err)
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

			// Process dependency and collect result
			depResult := parseGoDependencyLineWithResult(line, token, config, timeCutoff, outputFormat)
			if depResult != nil {
				results = append(results, *depResult)
			}
		}
	}

	return results, scanner.Err()
}

// parseGoDependencyLineWithResult processes a dependency line and returns a DependencyReport
func parseGoDependencyLineWithResult(line string, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) *output.DependencyReport {
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "//") || line == "" {
		return nil
	}

	if idx := strings.Index(line, "//"); idx != -1 {
		line = line[:idx]
	}

	if !strings.HasPrefix(line, "github.com/") {
		fmt.Printf("Skipping non-github dependency (not implemented yet): %s\n\n", line)
		return &output.DependencyReport{
			Package: line,
			Version: "unknown",
			Status:  "SKIPPED",
			Issues:  []string{"Non-GitHub dependency not supported"},
		}
	}

	parts := strings.Fields(line)
	if len(parts) != 2 {
		return nil
	}

	rawRepo := parts[0]
	cleanedRepo := helpers.CleanGitHubURL(rawRepo)
	version := parts[1]
	version = strings.Split(version, "+")[0]

	// Handle replacements
	if replacement, ok := replaceMap[rawRepo]; ok {
		fmt.Printf("[INFO] Replaced module: %s → %s@%s\n", rawRepo, replacement.Repo, replacement.Version)
		cleanedRepo = helpers.CleanGitHubURL(replacement.Repo)
		version = replacement.Version
	}

	// Handle exclusions
	if excludedVersion, ok := excludeMap[cleanedRepo]; ok && excludedVersion == strings.TrimPrefix(version, "v") {
		fmt.Printf("Excluded: %s@%s (skipped)\n\n", cleanedRepo, version)
		return &output.DependencyReport{
			Package: cleanedRepo,
			Version: version,
			Status:  "EXCLUDED",
			Issues:  []string{"Excluded by go.mod"},
		}
	}

	// Handle pseudo-versions
	if strings.Contains(version, "-") && strings.HasPrefix(version, "v0.0.0-") {
		fmt.Printf("Pseudo-version detected, falling back to latest semver tag.\n")
		tag, _, err := helpers.FindLatestSemverTag(cleanedRepo, token)
		if err != nil {
			fmt.Printf("Error finding latest tag for %s: %v\n\n", cleanedRepo, err)
			return &output.DependencyReport{
				Package: cleanedRepo,
				Version: version,
				Status:  "ERROR",
				Issues:  []string{fmt.Sprintf("Failed to resolve pseudo-version: %v", err)},
			}
		}
		fmt.Printf("Resolved to tag: %s\n", tag)

		if excludedVersion, ok := excludeMap[cleanedRepo]; ok && excludedVersion == strings.TrimPrefix(tag, "v") {
			fmt.Printf("Excluded after resolving: %s@%s (skipped)\n\n", cleanedRepo, tag)
			return &output.DependencyReport{
				Package: cleanedRepo,
				Version: version,
				Status:  "EXCLUDED",
				Issues:  []string{"Excluded after pseudo-version resolution"},
			}
		}

		return &output.DependencyReport{
			Package: cleanedRepo,
			Version: version,
			Status:  "PSEUDO_VERSION",
			Issues:  []string{fmt.Sprintf("Resolved to tag: %s", tag)},
		}
	}

	// Get SHA from tag
	sha, err := helpers.GetSHAFromTag(cleanedRepo, version, token)
	if err != nil {
		fmt.Printf("Error getting SHA for %s@%s: %v\n\n", cleanedRepo, version, err)
		return &output.DependencyReport{
			Package: cleanedRepo,
			Version: version,
			Status:  "ERROR",
			Issues:  []string{fmt.Sprintf("Failed to get SHA: %v", err)},
		}
	}

	// Check signatures
	signatureResults, err := checksignature.CheckSignatureLocal(cleanedRepo, sha, config)
	if err != nil {
		fmt.Printf("Error checking signatures for %s: %v\n\n", cleanedRepo, err)
		return &output.DependencyReport{
			Package: cleanedRepo,
			Version: version,
			Status:  "ERROR",
			Issues:  []string{fmt.Sprintf("Signature check failed: %v", err)},
		}
	}

	// Process results
	summary := checksignature.ProcessSignatureResults(signatureResults, config)
	output.PrintDependencyConsoleOutput(summary, config, "go.mod", cleanedRepo, version, len(signatureResults), outputFormat)

	// Determine status and collect issues
	var status string
	var issues []string

	if len(signatureResults) == 0 {
		status = "SKIPPED"
		fmt.Printf("Dependency %s@%s: No relevant commits found that fit the criteria (skipped)\n", cleanedRepo, version)

	} else if summary.RejectedByPolicy > 0 {
		status = "FAILED"
		fmt.Printf("Dependency %s@%s rejected by policy\n", cleanedRepo, version)

		// Look for unsigned commits in status breakdown
		if statusCount, exists := summary.StatusBreakdown["unsigned"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d unsigned commits", statusCount))
		}

		// Look for missing keys
		if statusCount, exists := summary.StatusBreakdown["signed-but-missing-key"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d missing keys", statusCount))
		}

		// Look for expired keys
		if statusCount, exists := summary.StatusBreakdown["valid-but-expired-key"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d expired keys", statusCount))
		}

		// Look for uncertified signers
		if statusCount, exists := summary.StatusBreakdown["valid-but-not-certified"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d uncertified signers", statusCount))
		}

		// Look for unregistered keys
		if statusCount, exists := summary.StatusBreakdown["valid-but-key-not-on-github"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d unregistered keys", statusCount))
		}

		// Look for email mismatches
		if statusCount, exists := summary.StatusBreakdown["signed-but-untrusted-email"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d email mismatches", statusCount))
		}

		// Look for invalid signatures
		if statusCount, exists := summary.StatusBreakdown["invalid"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d invalid signatures", statusCount))
		}

		// Look for verification errors
		if statusCount, exists := summary.StatusBreakdown["error"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d verification errors", statusCount))
		}

		// Catch any other status types that might be added in the future
		for status, count := range summary.StatusBreakdown {
			if count > 0 && status != "valid" && status != "github-automated-signature" {
				// Check if we already handled this status
				knownStatuses := map[string]bool{
					"unsigned":                    true,
					"signed-but-missing-key":      true,
					"valid-but-expired-key":       true,
					"valid-but-not-certified":     true,
					"valid-but-key-not-on-github": true,
					"signed-but-untrusted-email":  true,
					"invalid":                     true,
					"error":                       true,
				}

				if !knownStatuses[status] {
					issues = append(issues, fmt.Sprintf("%d %s", count, status))
				}
			}
		}

		if len(issues) == 0 {
			issues = append(issues, fmt.Sprintf("%d commits rejected by policy", summary.RejectedByPolicy))
		}

	} else {
		status = "PASSED"
		fmt.Printf("Dependency %s@%s passed policy check\n", cleanedRepo, version)
	}

	fmt.Println()

	return &output.DependencyReport{
		Package:         cleanedRepo,
		Version:         version,
		Manifest:        "go.mod",
		Status:          status,
		Issues:          issues,
		CommitsChecked:  len(signatureResults),
		ValidSignatures: summary.ValidSignatures,
		Summary:         output.BuildSignatureAnalysis(summary, signatureResults),
		Commits:         output.BuildCommitAnalysis(signatureResults),
		Policy:          output.BuildPolicyConfiguration(config),
		KeyAgePolicy:    helpers.CreateKeyAgeRange(config),
		TimeRangePolicy: helpers.CreateTimeRange(timeCutoff),
	}
}
