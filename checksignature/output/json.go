package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
)

// HandleJSONOutput generates comprehensive JSON report
func HandleJSONOutput(summary SignatureSummary, config types.LocalCheckConfig, results []SignatureCheckResult, outputFile, context string) error {
	jsonData, err := ToJSON(summary, config, results)
	if err != nil {
		return err
	}

	if outputFile != "" {
		fmt.Printf("Saving detailed %s report to: %s\n", context, outputFile)
		return SaveJSON(summary, config, results, outputFile)
	} else {
		fmt.Printf("\n=== JSON REPORT (%s) ===\n", strings.ToUpper(context))
		fmt.Println(string(jsonData))
		return nil
	}
}

// ToJSON converts a SignatureSummary to a comprehensive JSON report
func ToJSON(summary SignatureSummary, config types.LocalCheckConfig, results []SignatureCheckResult) ([]byte, error) {
	report := &JSONReport{
		Metadata: ReportMetadata{
			GeneratedAt:  time.Now(),
			ToolVersion:  "1.0.0",
			AnalysisType: "signature_verification",
		},
		Repository: RepositoryInfo{
			Name:           config.Repo,
			Branch:         config.Branch,
			CommitsChecked: len(results),
		},
		Policy:  BuildPolicyConfiguration(config),
		Summary: BuildSignatureAnalysis(summary, results),
		Commits: BuildCommitAnalysis(results),
	}

	// Add time range if configured
	if config.TimeCutoff != nil {
		report.Repository.TimeRange = &TimeRange{
			From: *config.TimeCutoff,
			To:   time.Now(),
		}
	}

	// Add key age policy if configured
	if config.KeyCreationCutoff != nil {
		report.Repository.KeyAgePolicy = &TimeRange{
			From: *config.KeyCreationCutoff,
			To:   time.Now(),
		}
	}

	return json.MarshalIndent(report, "", "  ")
}

// PrintJSON outputs the analysis results in JSON format
func PrintJSON(summary SignatureSummary, config types.LocalCheckConfig, results []SignatureCheckResult) error {
	jsonData, err := ToJSON(summary, config, results)
	if err != nil {
		return fmt.Errorf("failed to generate JSON: %v", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// SaveJSON saves the analysis results to a JSON file
func SaveJSON(summary SignatureSummary, config types.LocalCheckConfig, results []SignatureCheckResult, filename string) error {
	jsonData, err := ToJSON(summary, config, results)
	if err != nil {
		return fmt.Errorf("failed to generate JSON: %v", err)
	}

	return writeToFile(filename, jsonData)
}

// buildPolicyConfiguration creates the policy section
func BuildPolicyConfiguration(config types.LocalCheckConfig) PolicyConfiguration {
	policy := PolicyConfiguration{
		AcceptExpiredKeys:       config.AcceptExpiredKeys,
		AcceptUnsignedCommits:   config.AcceptUnsignedCommits,
		AcceptEmailMismatches:   config.AcceptEmailMismatches,
		AcceptUncertifiedSigner: config.AcceptUncertifiedSigner,
		AcceptMissingPublicKey:  config.AcceptMissingPublicKey,
		AcceptGitHubAutomated:   config.AcceptGitHubAutomated,
		AcceptUnregisteredKeys:  config.AcceptUnregisteredKeys,
	}
	return policy
}

// buildSignatureAnalysis creates the summary analysis
func BuildSignatureAnalysis(summary SignatureSummary, results []SignatureCheckResult) SummaryStats {
	return SummaryStats{
		TotalCommits:     summary.TotalCommits,
		ValidSignatures:  summary.ValidSignatures,
		AcceptedByPolicy: summary.AcceptedByPolicy,
		RejectedByPolicy: summary.RejectedByPolicy,
		StatusBreakdown:  summary.StatusBreakdown,
		SecurityScore:    CalculateSecurityScore(summary),
	}
}

// buildCommitAnalysis creates detailed commit analysis
func BuildCommitAnalysis(results []SignatureCheckResult) []CommitAnalysis {
	var commits []CommitAnalysis

	for _, result := range results {
		commit := CommitAnalysis{
			SHA:             result.CommitSHA,
			Author:          result.Author,
			Timestamp:       result.Timestamp,
			SignatureStatus: result.Status,
			PolicyDecision:  result.AcceptedByPolicy,
			HardRejection:   result.HardPolicyViolation,
			RawOutput:       result.Output,
		}

		if result.Err != nil {
			commit.Error = result.Err.Error()
		}

		switch result.Status {
		case "valid":

		case "valid-but-expired-key":
			commit.SecurityFlags = append(commit.SecurityFlags, "expired_key")

		case "valid-but-not-certified":
			commit.SecurityFlags = append(commit.SecurityFlags, "uncertified_key")

		case "valid-but-key-not-on-github":
			commit.SecurityFlags = append(commit.SecurityFlags, "unregistered_key")

		case "github-automated-signature":
			commit.SecurityFlags = append(commit.SecurityFlags, "github_automated_signature")

		case "signed-but-untrusted-email":
			commit.SecurityFlags = append(commit.SecurityFlags, "email_mismatch")

		case "signed-but-missing-key":
			commit.SecurityFlags = append(commit.SecurityFlags, "missing_public_key")

		case "unsigned":
			commit.SecurityFlags = append(commit.SecurityFlags, "no_signature")

		case "invalid":
			commit.SecurityFlags = append(commit.SecurityFlags, "invalid_signature")

		case "error":
			commit.SecurityFlags = append(commit.SecurityFlags, "verification_error")

		default:
			commit.SecurityFlags = append(commit.SecurityFlags, "unknown_signature_status")
		}

		commits = append(commits, commit)
	}

	return commits
}

// writeToFile is a helper function to write data to a file
func writeToFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

// HandleCombinedJSONOutput generates a combined JSON report for both repository and dependencies
func HandleCombinedJSONOutput(
	repoSummary SignatureSummary,
	repoConfig types.LocalCheckConfig,
	repoResults []SignatureCheckResult,
	dependencyResults []DependencyReport,
	outputFile string,
) error {
	// Generate combined JSON with both repository and dependencies
	jsonData, err := ToCombinedJSON(repoSummary, repoConfig, repoResults, dependencyResults)
	if err != nil {
		return err
	}

	if outputFile != "" {
		fmt.Printf("Saving combined security report to: %s\n", outputFile)
		return writeToFile(outputFile, jsonData)
	} else {
		fmt.Printf("\n=== COMBINED JSON REPORT ===\n")
		fmt.Println(string(jsonData))
		return nil
	}
}

// ToCombinedJSON creates a comprehensive JSON report combining repository and dependency analysis
func ToCombinedJSON(
	repoSummary SignatureSummary,
	repoConfig types.LocalCheckConfig,
	repoResults []SignatureCheckResult,
	dependencyResults []DependencyReport,
) ([]byte, error) {
	report := &JSONReport{
		Metadata: ReportMetadata{
			GeneratedAt:  time.Now(),
			ToolVersion:  "1.0.0",
			AnalysisType: "signature_verification",
		},
		Repository: RepositoryInfo{
			Name:           repoConfig.Repo,
			Branch:         repoConfig.Branch,
			CommitsChecked: len(repoResults),
		},
		Policy:       BuildPolicyConfiguration(repoConfig),
		Summary:      BuildSignatureAnalysis(repoSummary, repoResults),
		Commits:      BuildCommitAnalysis(repoResults),
		Dependencies: dependencyResults,
	}

	// Add time range if configured
	if repoConfig.TimeCutoff != nil {
		report.Repository.TimeRange = &TimeRange{
			From: *repoConfig.TimeCutoff,
			To:   time.Now(),
		}
	}

	// Add key age policy if configured
	if repoConfig.KeyCreationCutoff != nil {
		report.Repository.KeyAgePolicy = &TimeRange{
			From: *repoConfig.KeyCreationCutoff,
			To:   time.Now(),
		}
	}

	return json.MarshalIndent(report, "", "  ")
}
