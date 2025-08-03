package output

import "time"

// SignatureSummary contains aggregated signature verification results
type SignatureSummary struct {
	TotalCommits     int
	ValidSignatures  int
	AcceptedByPolicy int
	RejectedByPolicy int
	StatusBreakdown  map[string]int
	FailedCommits    []string
}

type JSONReport struct {
	Metadata     ReportMetadata      `json:"metadata"`
	Repository   RepositoryInfo      `json:"repository"`
	Policy       PolicyConfiguration `json:"policy"`
	Summary      SummaryStats        `json:"summary"`
	Commits      []CommitAnalysis    `json:"commits"`
	Dependencies []DependencyReport  `json:"dependencies,omitempty"`
}

// ContributorSummary contains analysis of a single contributor's keys
type ContributorSummary struct {
	Username        string
	KeyCount        int
	RecentKeys      int
	SuspiciousKeys  []KeyInfo
	TotalSuspicious int
}

// KeyInfo represents information about a specific key
type KeyInfo struct {
	Type        string
	Fingerprint string
	CreatedAt   string
	Title       string
}

// SecurityReport contains comprehensive security analysis
type SecurityReport struct {
	Repository          string
	SignatureSummary    SignatureSummary
	ContributorAnalysis map[string]ContributorSummary
	SecurityRisks       []SecurityRisk
}

// SecurityRisk represents a potential security concern
type SecurityRisk struct {
	Level       RiskLevel
	Description string
	Affected    []string
}

// RiskLevel represents the severity of a security risk
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type SignatureCheckResult struct {
	CommitSHA string
	Status    string // e.g., "valid", "unsigned", "invalid"
	Output    string // raw gpg/ssh output
	Err       error

	Author    AuthorInfo
	Timestamp time.Time

	AcceptedByPolicy    bool
	HardPolicyViolation bool
}

type PolicyConfig struct {
	AcceptExpiredKeys         bool `json:"accept_expired_keys"`
	AcceptUnsignedCommits     bool `json:"accept_unsigned_commits"`
	AcceptUntrustedSigners    bool `json:"accept_untrusted_signers"`
	AcceptUncertifiedKeys     bool `json:"accept_uncertified_keys"`
	AcceptMissingPublicKey    bool `json:"accept_missing_public_key"`
	AcceptGitHubAutomated     bool `json:"accept_github_automated"`
	AcceptUnauthorizedSigners bool `json:"accept_unauthorized_signatures"`
}

type SummaryStats struct {
	TotalCommits     int            `json:"total_commits"`
	ValidSignatures  int            `json:"valid_signatures"`
	AcceptedByPolicy int            `json:"accepted_by_policy"`
	RejectedByPolicy int            `json:"rejected_by_policy"`
	StatusBreakdown  map[string]int `json:"status_breakdown"`
	SecurityScore    float64        `json:"security_score"`
}

type DependencyReport struct {
	Package         string              `json:"package"`
	Version         string              `json:"version"`
	Manifest        string              `json:"manifest"`
	CommitsChecked  int                 `json:"commits_checked"`
	TimeRange       *TimeRange          `json:"time_cutoff_policy,omitempty"`
	KeyAgePolicy    *TimeRange          `json:"key_age_policy,omitempty"`
	TimeRangePolicy *TimeRange          `json:"time_range_policy,omitempty"` // NEW FIELD
	Policy          PolicyConfiguration `json:"policy"`
	Summary         SummaryStats        `json:"summary"`
	Status          string              `json:"status"`
	ValidSignatures int                 `json:"fully_valid_signatures,omitempty"`
	Commits         []CommitAnalysis    `json:"commits"`
	Issues          []string            `json:"issues,omitempty"`
}

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
	TotalCommits     int            `json:"total_commits"`
	ValidSignatures  int            `json:"valid_signatures"`
	AcceptedByPolicy int            `json:"accepted_by_policy"`
	RejectedByPolicy int            `json:"rejected_by_policy"`
	StatusBreakdown  map[string]int `json:"status_breakdown"`
	SecurityScore    float64        `json:"security_score"`
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
	SHA             string     `json:"sha"`
	Author          AuthorInfo `json:"author"`
	Timestamp       time.Time  `json:"timestamp"`
	SignatureStatus string     `json:"signature_status"`
	PolicyDecision  bool       `json:"policy_decision"`
	HardRejection   bool       `json:"hard_rejection"`
	SecurityFlags   []string   `json:"security_flags,omitempty"`
	RawOutput       string     `json:"raw_output,omitempty"`
	Error           string     `json:"error,omitempty"`
}

// AuthorInfo contains information about the commit author
type AuthorInfo struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
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

type CommitFailure struct {
	SHA         string
	Description string
}

type ContributorAnalysis struct {
	Username           string
	TotalKeys          int
	RecentKeysCount    int
	RecentKeysDays     int
	CommitsWithNewKeys int
	LastCommitDate     time.Time
}
