package output

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
	Summary      SignatureAnalysis   `json:"summary"`
	Commits      []CommitAnalysis    `json:"commits"`
	Dependencies []DependencyReport  `json:"dependencies,omitempty"`
}

// Add new dependency structure:
type DependencyReport struct {
	Package         string              `json:"package"`
	Version         string              `json:"version"`
	Name            string              `json:"name"`
	Manifest        string              `json:"manifest"`
	Status          string              `json:"status"` // "PASSED", "FAILED", "ERROR", "SKIPPED", "EXCLUDED"
	CommitsChecked  int                 `json:"commits_checked"`
	Summary         SignatureAnalysis   `json:"summary"`
	Commits         []CommitAnalysis    `json:"commits"`
	Policy          PolicyConfiguration `json:"policy"`
	Issues          []string            `json:"issues,omitempty"`
	SecurityScore   float64             `json:"security_score,omitempty"`
	ValidSignatures int                 `json:"valid_signatures,omitempty"`
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
