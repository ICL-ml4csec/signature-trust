package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
)

// ReportMetadata contains information about when and how the analysis was performed
type ReportMetadata struct {
	GeneratedAt   time.Time `json:"generated_at"`
	ToolVersion   string    `json:"tool_version"`
	AnalysisType  string    `json:"analysis_type"`
	ExecutionTime float64   `json:"execution_time_seconds,omitempty"`
}

// RepositoryInfo contains information about the analyzed repository
type RepositoryInfo struct {
	Name           string     `json:"name"`
	Branch         string     `json:"branch"`
	CommitsChecked int        `json:"commits_checked"`
	TimeRange      *TimeRange `json:"time_range,omitempty"`
	KeyAgePolicy   *TimeRange `json:"key_age_policy,omitempty"`
}

// TimeRange represents a time-based analysis range
type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// PolicyConfiguration shows what security policies were applied
type PolicyConfiguration struct {
	AcceptExpiredKeys       bool `json:"accept_expired_keys"`
	AcceptUnsignedCommits   bool `json:"accept_unsigned_commits"`
	AcceptEmailMismatches   bool `json:"accept_untrusted_signers"`
	AcceptUncertifiedSigner bool `json:"accept_uncertified_keys"`
	AcceptMissingPublicKey  bool `json:"accept_missing_public_key"`
	AcceptGitHubAutomated   bool `json:"accept_github_automated"`
	AcceptUnregisteredKeys  bool `json:"accept_unauthorized_signatures"`
}

// SignatureAnalysis provides high-level statistics
type SignatureAnalysis struct {
	TotalCommits     int                    `json:"total_commits"`
	ValidSignatures  int                    `json:"valid_signatures"`
	AcceptedByPolicy int                    `json:"accepted_by_policy"`
	RejectedByPolicy int                    `json:"rejected_by_policy"`
	StatusBreakdown  map[string]int         `json:"status_breakdown"`
	SignatureTypes   SignatureTypeBreakdown `json:"signature_types"`
	SecurityScore    float64                `json:"security_score"`
}

// SignatureTypeBreakdown shows distribution of signature types
type SignatureTypeBreakdown struct {
	GPGSignatures int `json:"gpg_signatures"`
	SSHSignatures int `json:"ssh_signatures"`
	DualSigned    int `json:"dual_signed"`
	Unsigned      int `json:"unsigned"`
}

// CommitAnalysis contains detailed information about each commit
type CommitAnalysis struct {
	SHA              string            `json:"sha"`
	Author           AuthorInfo        `json:"author"`
	Timestamp        time.Time         `json:"timestamp"`
	Message          string            `json:"message"`
	SignatureStatus  string            `json:"signature_status"`
	SignatureType    string            `json:"signature_type"`
	SignatureDetails *SignatureDetails `json:"signature_details,omitempty"`
	PolicyDecision   PolicyDecision    `json:"policy_decision"`
	SecurityFlags    []string          `json:"security_flags,omitempty"`
	RawOutput        string            `json:"raw_output,omitempty"`
	Error            string            `json:"error,omitempty"`
}

// AuthorInfo contains information about the commit author
type AuthorInfo struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	GitHubUser  string `json:"github_user,omitempty"`
	IsAutomated bool   `json:"is_automated"`
}

// SignatureDetails provides specific information about the signature
type SignatureDetails struct {
	KeyID            string     `json:"key_id,omitempty"`
	KeyType          string     `json:"key_type,omitempty"`
	KeyFingerprint   string     `json:"key_fingerprint,omitempty"`
	SignerEmail      string     `json:"signer_email,omitempty"`
	SignerName       string     `json:"signer_name,omitempty"`
	KeyCreatedAt     *time.Time `json:"key_created_at,omitempty"`
	KeyExpiresAt     *time.Time `json:"key_expires_at,omitempty"`
	EmailMatch       bool       `json:"email_match"`
	GitHubAuthorized bool       `json:"github_authorized"`
	TrustLevel       string     `json:"trust_level"`
}

// PolicyDecision shows how the policy system evaluated this commit
type PolicyDecision struct {
	Accepted    bool   `json:"accepted"`
	Reason      string `json:"reason"`
	RuleApplied string `json:"rule_applied"`
}

// DependencyInfo contains information about third-party dependencies
type DependencyInfo struct {
	Name               string    `json:"name"`
	Version            string    `json:"version"`
	Type               string    `json:"type"`
	Source             string    `json:"source"`
	LastUpdated        time.Time `json:"last_updated"`
	KnownVulns         int       `json:"known_vulnerabilities"`
	SecurityScore      float64   `json:"security_score"`
	RecommendedVersion string    `json:"recommended_version,omitempty"`
}

// HandleJSONOutput generates comprehensive JSON report
func HandleJSONOutput(summary SignatureSummary, config types.LocalCheckConfig, results []types.SignatureCheckResult, outputFile, context string) error {
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
func ToJSON(summary SignatureSummary, config types.LocalCheckConfig, results []types.SignatureCheckResult) ([]byte, error) {
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
		Policy:  buildPolicyConfiguration(config),
		Summary: buildSignatureAnalysis(summary, results),
		Commits: buildCommitAnalysis(results),
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
func PrintJSON(summary SignatureSummary, config types.LocalCheckConfig, results []types.SignatureCheckResult) error {
	jsonData, err := ToJSON(summary, config, results)
	if err != nil {
		return fmt.Errorf("failed to generate JSON: %v", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// SaveJSON saves the analysis results to a JSON file
func SaveJSON(summary SignatureSummary, config types.LocalCheckConfig, results []types.SignatureCheckResult, filename string) error {
	jsonData, err := ToJSON(summary, config, results)
	if err != nil {
		return fmt.Errorf("failed to generate JSON: %v", err)
	}

	return writeToFile(filename, jsonData)
}

// buildPolicyConfiguration creates the policy section
func buildPolicyConfiguration(config types.LocalCheckConfig) PolicyConfiguration {
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
func buildSignatureAnalysis(summary SignatureSummary, results []types.SignatureCheckResult) SignatureAnalysis {
	analysis := SignatureAnalysis{
		TotalCommits:     summary.TotalCommits,
		ValidSignatures:  summary.ValidSignatures,
		AcceptedByPolicy: summary.AcceptedByPolicy,
		RejectedByPolicy: summary.RejectedByPolicy,
		StatusBreakdown:  summary.StatusBreakdown,
		SecurityScore:    CalculateSecurityScore(summary),
	}

	return analysis
}

// buildCommitAnalysis creates detailed commit analysis
func buildCommitAnalysis(results []types.SignatureCheckResult) []CommitAnalysis {
	var commits []CommitAnalysis

	for _, result := range results {
		commit := CommitAnalysis{
			SHA:             result.CommitSHA,
			SignatureStatus: result.Status,
			PolicyDecision: PolicyDecision{
				Accepted: result.Err == nil && result.Status != "invalid",
				Reason:   result.Output,
			},
			RawOutput: result.Output,
		}

		if result.Err != nil {
			commit.Error = result.Err.Error()
		}

		// Add security flags based on status
		switch result.Status {
		case "signed-but-missing-key":
			commit.SecurityFlags = append(commit.SecurityFlags, "missing_public_key")
		case "signed-but-untrusted-email":
			commit.SecurityFlags = append(commit.SecurityFlags, "email_mismatch")
		case "valid-but-not-authorized":
			commit.SecurityFlags = append(commit.SecurityFlags, "unauthorized_signer")
		case "unsigned":
			commit.SecurityFlags = append(commit.SecurityFlags, "no_signature")
		case "invalid":
			commit.SecurityFlags = append(commit.SecurityFlags, "invalid_signature")
		}

		commits = append(commits, commit)
	}

	return commits
}

// writeToFile is a helper function to write data to a file
func writeToFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

func HandleCombinedJSONOutput(
	repoSummary SignatureSummary,
	repoConfig types.LocalCheckConfig,
	repoResults []types.SignatureCheckResult,
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

func ToCombinedJSON(
	repoSummary SignatureSummary,
	repoConfig types.LocalCheckConfig,
	repoResults []types.SignatureCheckResult,
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
		Policy:       buildPolicyConfiguration(repoConfig),
		Summary:      buildSignatureAnalysis(repoSummary, repoResults),
		Commits:      buildCommitAnalysis(repoResults),
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
