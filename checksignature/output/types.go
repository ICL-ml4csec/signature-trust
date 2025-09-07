package output

import (
	"time"

	"github.com/ICL-ml4csec/signature-trust/checksignature/types"
)

// SignatureSummary summarizes signature check results for a repository
type SignatureSummary struct {
	TotalCommits     int
	ValidSignatures  int
	AcceptedByPolicy int
	RejectedByPolicy int
	StatusBreakdown  map[types.SignatureStatus]int
	FailedCommits    []string
}

// JSONReport is the top-level structure for full output reporting
type JSONReport struct {
	Metadata     ReportMetadata      `json:"metadata"`
	Repository   RepositoryInfo      `json:"repository"`
	Policy       PolicyConfiguration `json:"policy"`
	Summary      SummaryStats        `json:"summary"`
	Commits      []CommitAnalysis    `json:"commits"`
	Dependencies []DependencyReport  `json:"dependencies,omitempty"`
}

// SignatureCheckResult holds results of checking a single commit
type SignatureCheckResult struct {
	CommitSHA           string
	Status              types.SignatureStatus
	Output              string
	Err                 error
	Author              AuthorInfo
	Timestamp           time.Time
	AcceptedByPolicy    bool
	HardPolicyViolation bool
}

// SummaryStats aggregates signature validation metrics
type SummaryStats struct {
	TotalCommits     int                           `json:"total_commits"`
	ValidSignatures  int                           `json:"valid_signatures"`
	AcceptedByPolicy int                           `json:"accepted_by_policy"`
	RejectedByPolicy int                           `json:"rejected_by_policy"`
	StatusBreakdown  map[types.SignatureStatus]int `json:"status_breakdown"`
	SecurityScore    float64                       `json:"security_score"`
}

// DependencyReport describes signature results for a third-party dependency
type DependencyReport struct {
	Package         string              `json:"package"`
	Version         string              `json:"version"`
	Manifest        string              `json:"manifest"`
	Source          string              `json:"source"`
	CommitsChecked  int                 `json:"commits_checked"`
	TimeRange       *TimeRange          `json:"time_cutoff_policy,omitempty"`
	KeyAgePolicy    *TimeRange          `json:"key_age_policy,omitempty"`
	TimeRangePolicy *TimeRange          `json:"time_range_policy,omitempty"`
	Policy          PolicyConfiguration `json:"policy"`
	Summary         SummaryStats        `json:"summary"`
	Status          string              `json:"status"`
	ValidSignatures int                 `json:"fully_valid_signatures,omitempty"`
	Commits         []CommitAnalysis    `json:"commits"`
	Issues          []string            `json:"issues,omitempty"`
}

// ReportMetadata provides run-time information about the analysis
type ReportMetadata struct {
	GeneratedAt   time.Time `json:"generated_at"`
	ToolVersion   string    `json:"tool_version"`
	AnalysisType  string    `json:"analysis_type"`
	ExecutionTime float64   `json:"execution_time_seconds,omitempty"`
}

// RepositoryInfo describes the scanned repository and its analysis scope
type RepositoryInfo struct {
	Name           string     `json:"name"`
	Branch         string     `json:"branch"`
	CommitsChecked int        `json:"commits_checked"`
	TimeRange      *TimeRange `json:"time_range,omitempty"`
	KeyAgePolicy   *TimeRange `json:"key_age_policy,omitempty"`
}

// TimeRange defines a from–to window for commit/key analysis
type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// PolicyConfiguration reflects the signature acceptance rules used
type PolicyConfiguration struct {
    AcceptExpiredKeys      bool `json:"accept_expired_keys"`
    AcceptUnsignedCommits  bool `json:"accept_unsigned_commits"`
    AcceptEmailMismatch    bool `json:"accept_email_mismatch"`
    AcceptUncertifiedKeys  bool `json:"accept_uncertified_keys"`
    AcceptMissingPublicKey bool `json:"accept_missing_public_key"`
    AcceptGitHubAutomated  bool `json:"accept_github_automated"`
    AcceptUnregisteredKeys bool `json:"accept_unregistered_keys"`
}

// CommitAnalysis stores per-commit evaluation and decisions
type CommitAnalysis struct {
	SHA             string                `json:"sha"`
	Author          AuthorInfo            `json:"author"`
	Timestamp       time.Time             `json:"timestamp"`
	SignatureStatus types.SignatureStatus `json:"signature_status"`
	PolicyDecision  bool                  `json:"policy_decision"`
	HardRejection   bool                  `json:"hard_rejection"`
	SecurityFlags   []string              `json:"security_flags,omitempty"`
	RawOutput       string                `json:"raw_output,omitempty"`
	Error           string                `json:"error,omitempty"`
}

// AuthorInfo provides identity details for a commit author
type AuthorInfo struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	IsAutomated bool   `json:"is_automated"`
}

// CommitFailure represents an error encountered while checking a commit
type CommitFailure struct {
	SHA         string
	Description string
}
