package checksignature

import (
	"fmt"

	"github.com/ICL-ml4csec/signature-trust/checksignature/types"
)

// IsSignatureAcceptable determines if a signature status should be accepted based on config
func IsSignatureAcceptable(status types.SignatureStatus, config types.LocalCheckConfig) (bool, string) {
	switch status {
	case types.ValidSignature:
		return true, "Valid signature"

	case types.ValidSignatureButExpiredKey:
		if config.AcceptExpiredKeys {
			return true, "Expired key accepted by policy"
		}
		return false, "Expired key rejected by policy"

	case types.ValidSignatureButSignerNotCertified:
		if config.AcceptUncertifiedSigner {
			return true, "Uncertified key accepted by policy"
		}
		return false, "Uncertified key rejected by policy"

	case types.ValidSignatureButUnregisteredKey:
		if config.AcceptUnregisteredKeys {
			return true, "Unauthorized signature accepted by policy"
		}
		return false, "Valid signature but key not on GitHub account"

	case types.MissingPublicKey:
		if config.AcceptMissingPublicKey {
			return true, "Missing public key accepted by policy"
		}
		return false, "Missing public key rejected by policy"

	case types.EmailNotMatched:
		if config.AcceptEmailMismatches {
			return true, "Email mismatch accepted by policy"
		}
		return false, "Email mismatch rejected by policy"

	case types.GitHubAutomatedSignature:
		if config.AcceptGitHubAutomated {
			return true, "GitHub automated signature accepted by policy"
		}
		return false, "GitHub automated signature rejected by policy"

	case types.UnsignedCommit:
		if config.AcceptUnsignedCommits {
			return true, "Unsigned commit accepted by policy"
		}
		return false, "Unsigned commit rejected by policy"

	case types.InvalidSignature:
		return false, "Invalid signature (cryptographically broken)"

	case types.VerificationError:
		return false, "Verification error (technical failure)"

	default:
		return false, fmt.Sprintf("Unknown signature status: %s", status)
	}
}
