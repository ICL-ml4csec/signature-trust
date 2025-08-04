package ssh

import (
	"crypto/ed25519"
	"fmt"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
)

// VerifyEd25519 verifies an Ed25519 SSH signature
func VerifyEd25519(sshSig *types.SSHSignatureData, content string, isSecurityKey bool) (types.SignatureStatus, string, error) {
	keyTypeDesc := "Ed25519"
	if isSecurityKey {
		keyTypeDesc = "security key Ed25519"
	}

	publicKey, signature, err := extractEd25519KeyAndSignature(sshSig)
	if err != nil {
		return types.VerificationError, "", fmt.Errorf("failed to extract %s data: %v", keyTypeDesc, err)
	}

	signedPayload, err := computeSignedPayload(content, sshSig.Namespace, sshSig.HashAlgorithm)
	if err != nil {
		return types.VerificationError, "", fmt.Errorf("failed to compute payload: %v", err)
	}

	valid := ed25519.Verify(publicKey, signedPayload, signature)

	if valid {
		authorEmail := utils.ExtractAuthorEmail(content)
		return types.ValidSignature, fmt.Sprintf("Valid %s SSH signature for %s", keyTypeDesc, authorEmail), nil
	}

	return types.InvalidSignature, fmt.Sprintf("%s SSH signature verification failed", keyTypeDesc), nil
}
