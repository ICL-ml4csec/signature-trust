package ssh

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/ICL-ml4csec/signature-trust/checksignature/types"
	"github.com/ICL-ml4csec/signature-trust/checksignature/utils"
)

// VerifyECDSAP256 verifies an ECDSA P-256 SSH signature
func VerifyECDSAP256(sshSig *types.SSHSignatureData, content string, isSecurityKey bool) (types.SignatureStatus, string, error) {
	keyTypeDesc := "ECDSA P-256"
	if isSecurityKey {
		keyTypeDesc = "security key ECDSA P-256"
	}

	publicKey, r, s, err := extractECDSAKeyAndSignature(sshSig)
	if err != nil {
		return types.VerificationError, "", fmt.Errorf("failed to extract %s data: %v", keyTypeDesc, err)
	}

	signedPayload, err := computeSignedPayload(content, sshSig.Namespace, sshSig.HashAlgorithm)
	if err != nil {
		return types.VerificationError, "", fmt.Errorf("failed to compute payload: %v", err)
	}

	hash := sha256.Sum256(signedPayload)

	valid := ecdsa.Verify(publicKey, hash[:], r, s)

	if valid {
		authorEmail := utils.ExtractAuthorEmail(content)
		return types.ValidSignature, fmt.Sprintf("Valid %s SSH signature for %s", keyTypeDesc, authorEmail), nil
	}

	return types.InvalidSignature, fmt.Sprintf("%s SSH signature verification failed", keyTypeDesc), nil
}
