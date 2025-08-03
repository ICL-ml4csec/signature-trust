package types

import "time"

type SignatureStatus string

const (
	ValidSignature                      SignatureStatus = "valid"
	ValidSignatureButExpiredKey         SignatureStatus = "valid-but-expired-key"
	ValidSignatureButSignerNotCertified SignatureStatus = "valid-but-not-certified"
	ValidSignatureButUnregisteredKey    SignatureStatus = "valid-but-key-not-on-github"
	GitHubAutomatedSignature            SignatureStatus = "github-automated-signature"
	EmailNotMatched                     SignatureStatus = "signed-but-untrusted-email"
	MissingPublicKey                    SignatureStatus = "signed-but-missing-key"
	UnsignedCommit                      SignatureStatus = "unsigned"
	InvalidSignature                    SignatureStatus = "invalid"
	VerificationError                   SignatureStatus = "error"
)

type LocalCheckConfig struct {
	Branch                  string
	Token                   string
	Repo                    string
	CommitsToCheck          int
	AcceptExpiredKeys       bool
	AcceptUnsignedCommits   bool
	AcceptEmailMismatches   bool
	AcceptUncertifiedSigner bool
	AcceptMissingPublicKey  bool
	AcceptGitHubAutomated   bool
	AcceptUnregisteredKeys  bool
	TimeCutoff              *time.Time
	KeyCreationCutoff       *time.Time
}

type GitHubGPGKey struct {
	ID           int         `json:"id"`
	PrimaryKeyID interface{} `json:"primary_key_id"`
	KeyID        string      `json:"key_id"`
	PublicKey    string      `json:"public_key"`
	Emails       []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	} `json:"emails"`
	Subkeys []struct {
		ID                int         `json:"id"`
		PrimaryKeyID      interface{} `json:"primary_key_id"`
		KeyID             string      `json:"key_id"`
		PublicKey         string      `json:"public_key"`
		CanSign           bool        `json:"can_sign"`
		CanEncryptComms   bool        `json:"can_encrypt_comms"`
		CanEncryptStorage bool        `json:"can_encrypt_storage"`
		CanCertify        bool        `json:"can_certify"`
		CreatedAt         time.Time   `json:"created_at"`
		ExpiresAt         *time.Time  `json:"expires_at"`
	} `json:"subkeys"`
	CanSign           bool       `json:"can_sign"`
	CanEncryptComms   bool       `json:"can_encrypt_comms"`
	CanEncryptStorage bool       `json:"can_encrypt_storage"`
	CanCertify        bool       `json:"can_certify"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         *time.Time `json:"expires_at"`
}

type SSHSignatureData struct {
	ArmoredSignature string
	SignatureBlob    []byte
	Namespace        string
	HashAlgorithm    string
	PublicKey        []byte
	Signature        []byte
	IdentityComment  string
}

type KeyAnalysisResult struct {
	Username        string
	KeyCount        int
	RecentKeys      []GitHubUserKey
	OldKeys         []GitHubUserKey
	TotalSuspicious int
}

type GitHubUserKey struct {
	ID          int       `json:"id"`
	Key         string    `json:"key"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
	Title       string    `json:"title"`
}
