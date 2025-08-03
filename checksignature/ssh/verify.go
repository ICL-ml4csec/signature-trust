package ssh

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
	"github.com/ICL-ml4csec/msc-hmj24/trustpolicies"
)

// computeSignedPayload computes the SSH signed payload for verification
func computeSignedPayload(content, namespace, hashAlgorithm string) ([]byte, error) {
	cleanCommit := utils.RemoveSignatureFromCommit(content)

	var hasher hash.Hash
	switch hashAlgorithm {
	case "sha256":
		hasher = sha256.New()
	case "sha512":
		hasher = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlgorithm)
	}

	hasher.Write([]byte(cleanCommit))
	messageHash := hasher.Sum(nil)

	var payload bytes.Buffer

	payload.WriteString("SSHSIG")

	writeString := func(s string) {
		data := []byte(s)
		binary.Write(&payload, binary.BigEndian, uint32(len(data)))
		payload.Write(data)
	}

	writeBytes := func(data []byte) {
		binary.Write(&payload, binary.BigEndian, uint32(len(data)))
		payload.Write(data)
	}

	writeString(namespace)
	writeString("")
	writeString(hashAlgorithm)
	writeBytes(messageHash)

	return payload.Bytes(), nil
}

// Verify performs complete SSH signature verification
func Verify(raw []byte, sha string, config types.LocalCheckConfig) (types.SignatureStatus, string, error) {
	content := string(raw)

	if !strings.Contains(content, "gpgsig -----BEGIN SSH SIGNATURE-----") {
		return types.UnsignedCommit, "No SSH signature found", nil
	}

	sshSig, err := ExtractSignatureData(content)
	if err != nil {
		return types.VerificationError, fmt.Sprintf("Failed to parse SSH signature: %v", err), err
	}

	if config.Token != "" && config.Repo != "" && sha != "" {
		ok, createdAt, err := trustpolicies.GetSSHKeyCreationTime(sshSig.PublicKey, config.Repo, sha, config.Token, config.KeyCreationCutoff)
		if err != nil {
			fingerprint, fpErr := utils.ComputeFingerprintFlexible(sshSig.PublicKey)
			if fpErr != nil {
				fingerprint = "unknown"
			}
			return types.MissingPublicKey, fmt.Sprintf("SSH signing key %s not found in GitHub account: %v", fingerprint, err), nil
		}
		if !ok {
			fingerprint, fpErr := utils.ComputeFingerprintFlexible(sshSig.PublicKey)
			if fpErr != nil {
				fingerprint = "unknown"
			}
			return types.InvalidSignature, fmt.Sprintf("Key %s created too recently (%s)", fingerprint, createdAt.Format("2006-01-02T15:04:05Z07:00")), nil
		}
	}

	keyType, err := GetKeyType(sshSig.PublicKey)
	if err != nil {
		return types.VerificationError, fmt.Sprintf("Failed to determine key type: %v", err), err
	}

	// Check for GitHub automated commits
	if trustpolicies.IsGitHubAutomatedCommit("", content, sshSig) {
		return types.GitHubAutomatedSignature, "GitHub automated SSH signature detected", nil
	}

	// Perform cryptographic verification based on key type
	var status types.SignatureStatus
	var output string
	var verifyErr error
	switch keyType {
	case "ssh-ed25519":
		status, output, verifyErr = VerifyEd25519(sshSig, content, false)
	case "sk-ssh-ed25519@openssh.com":
		status, output, verifyErr = VerifyEd25519(sshSig, content, true)
	case "ecdsa-sha2-nistp256":
		status, output, verifyErr = VerifyECDSAP256(sshSig, content, false)
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		status, output, verifyErr = VerifyECDSAP256(sshSig, content, true)
	case "ssh-rsa":
		return types.ValidSignatureButSignerNotCertified, "SSH-RSA signatures are not supported for commit signing (deprecated by GitHub for security reasons). Use Ed25519: ssh-keygen -t ed25519", nil
	case "ssh-dss":
		return types.InvalidSignature, "SSH-DSS keys are cryptographically broken and not supported", nil
	case "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return types.ValidSignatureButSignerNotCertified,
			fmt.Sprintf("ECDSA %s curves not supported. GitHub only supports nistp256 for ECDSA. Consider Ed25519 instead.",
				strings.TrimPrefix(keyType, "ecdsa-sha2-")), nil
	default:
		return types.VerificationError, fmt.Sprintf("Unknown SSH key type: %s", keyType), nil
	}

	// Check email/identity matching for valid signatures
	if status == types.ValidSignature {
		signerIdentity := sshSig.IdentityComment
		isSecurityKey := strings.Contains(keyType, "sk-")

		// Skip email check for security keys (hardware-bound, different threat model)
		if !isSecurityKey && signerIdentity != "" {
			mismatch, signerEmail, authorEmail := utils.CheckEmailMismatch(raw, output)
			if mismatch {
				return types.EmailNotMatched, fmt.Sprintf("Signer <%s> does not match author <%s>", signerEmail, authorEmail), verifyErr
			}
		}
	}

	return status, output, verifyErr
}
