package types

import "time"

type SignatureStatus string

const (
	ValidSignature                      SignatureStatus = "valid"                       // Cryptographically valid and fully trusted
	ValidSignatureButExpiredKey         SignatureStatus = "valid-but-expired-key"       // Signature valid but key is expired
	ValidSignatureButSignerNotCertified SignatureStatus = "valid-but-not-certified"     // Signature valid but signer lacks certification
	ValidSignatureButUnregisteredKey    SignatureStatus = "valid-but-key-not-on-github" // Signature valid but key not linked to GitHub account
	GitHubAutomatedSignature            SignatureStatus = "github-automated-signature"  // Valid GitHub automated commit
	EmailNotMatched                     SignatureStatus = "signed-but-untrusted-email"  // Signer's email doesn't match commit author
	MissingPublicKey                    SignatureStatus = "signed-but-missing-key"      // Cannot find public key for verification
	UnsignedCommit                      SignatureStatus = "unsigned"                    // No signature found in commit
	InvalidSignature                    SignatureStatus = "invalid"                     // Signature found but cryptographically invalid
	VerificationError                   SignatureStatus = "error"                       // Internal or parsing error during verification
)

// LocalCheckConfig defines trust policy and verification options for signature checks
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
	OriginalTimePeriod      string
	OriginalKeyPeriod       string
}

// GitHubGPGKey represents a GPG key retrieved from the GitHub API
type GitHubGPGKey struct {
	ID           int         `json:"id"`
	PrimaryKeyID interface{} `json:"primary_key_id"`
	KeyID        string      `json:"key_id"`
	RawKey       string      `json:"raw_key"`
	PublicKey    string      `json:"public_key"`
	Emails       []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	} `json:"emails"`
	Subkeys []struct {
		ID                int         `json:"id"`
		PrimaryKeyID      interface{} `json:"primary_key_id"`
		KeyID             string      `json:"key_id"`
		RawKey            string      `json:"raw_key"` // <-- add this
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

// SSHSignatureData holds parsed information extracted from a commit's SSH signature
type SSHSignatureData struct {
	ArmoredSignature string
	SignatureBlob    []byte
	Namespace        string
	HashAlgorithm    string
	PublicKey        []byte
	Signature        []byte
	IdentityComment  string
}

// GitHubUserKey represents a user's SSH signing key fetched from the GitHub API
type GitHubUserKey struct {
	ID          int       `json:"id"`
	Key         string    `json:"key"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
	Title       string    `json:"title"`
}
