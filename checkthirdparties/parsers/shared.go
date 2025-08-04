package parsers

import (
	"fmt"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/output"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
)

// CheckSignaturesAndBuildReport checks signatures for a given package version and builds a detailed report
func CheckSignaturesAndBuildReport(repoInfo *helpers.RepoInfo, pkg, version, token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat, manifest string) *output.DependencyReport {
	// Get SHA from tag
	sha, err := helpers.GetSHAFromTag(repoInfo, version, token)
	if err != nil && !strings.HasPrefix(version, "v") {
		sha, err = helpers.GetSHAFromTag(repoInfo, "v"+version, token)
		version = "v" + version
	}
	if err != nil {
		fmt.Printf("Error getting SHA for %s@%s: %v\n", pkg, version, err)
		return &output.DependencyReport{
			Package:  repoInfo.FullName,
			Version:  version,
			Manifest: manifest,
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("Failed to get SHA: %v", err)},
		}
	}

	// Check signatures
	signatureResults, err := checksignature.CheckSignatureLocal(repoInfo.FullName, sha, config)
	if err != nil {
		fmt.Printf("Error checking signatures for %s: %v\n", repoInfo.FullName, err)
		return &output.DependencyReport{
			Package:  repoInfo.FullName,
			Version:  version,
			Manifest: manifest,
			Status:   "ERROR",
			Issues:   []string{fmt.Sprintf("Signature check failed: %v", err)},
		}
	}

	// Process results
	summary := checksignature.ProcessSignatureResults(signatureResults, config)
	output.PrintDependencyConsoleOutput(summary, config, manifest, repoInfo.FullName, version, len(signatureResults), outputFormat)

	// Determine status and collect issues
	var status string
	var issues []string

	if len(signatureResults) == 0 {
		status = "SKIPPED"
		fmt.Printf("Dependency %s@%s: No relevant commits found that fit the criteria (skipped)\n", repoInfo.FullName, version)
	} else if summary.RejectedByPolicy > 0 {
		status = "FAILED"
		fmt.Printf("Dependency %s@%s rejected by policy\n", repoInfo.FullName, version)

		// Collect issues using the same comprehensive logic as Go parser
		if statusCount, exists := summary.StatusBreakdown["unsigned"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d unsigned commits", statusCount))
		}
		if statusCount, exists := summary.StatusBreakdown["signed-but-missing-key"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d missing keys", statusCount))
		}
		if statusCount, exists := summary.StatusBreakdown["valid-but-expired-key"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d expired keys", statusCount))
		}
		if statusCount, exists := summary.StatusBreakdown["valid-but-not-certified"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d uncertified signers", statusCount))
		}
		if statusCount, exists := summary.StatusBreakdown["valid-but-key-not-on-github"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d unregistered keys", statusCount))
		}
		if statusCount, exists := summary.StatusBreakdown["signed-but-untrusted-email"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d email mismatches", statusCount))
		}
		if statusCount, exists := summary.StatusBreakdown["invalid"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d invalid signatures", statusCount))
		}
		if statusCount, exists := summary.StatusBreakdown["error"]; exists && statusCount > 0 {
			issues = append(issues, fmt.Sprintf("%d verification errors", statusCount))
		}

		if len(issues) == 0 {
			issues = append(issues, fmt.Sprintf("%d commits rejected by policy", summary.RejectedByPolicy))
		}
	} else {
		status = "PASSED"
		fmt.Printf("Dependency %s@%s passed policy check\n", repoInfo.FullName, version)
	}

	fmt.Println()

	return &output.DependencyReport{
		Package:         repoInfo.FullName,
		Version:         version,
		Manifest:        manifest,
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
