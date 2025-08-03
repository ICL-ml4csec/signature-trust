package ssh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"

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

// extractEd25519KeyAndSignature extracts Ed25519 public key and signature from SSH signature data
func extractEd25519KeyAndSignature(sshSig *types.SSHSignatureData) (ed25519.PublicKey, []byte, error) {
	pubKeyReader := bytes.NewReader(sshSig.PublicKey)

	var keyTypeLen uint32
	if err := binary.Read(pubKeyReader, binary.BigEndian, &keyTypeLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read key type length: %w", err)
	}

	keyType := make([]byte, keyTypeLen)
	if _, err := io.ReadFull(pubKeyReader, keyType); err != nil {
		return nil, nil, fmt.Errorf("failed to read key type: %w", err)
	}

	keyTypeStr := string(keyType)
	if keyTypeStr != "ssh-ed25519" && keyTypeStr != "sk-ssh-ed25519@openssh.com" {
		return nil, nil, fmt.Errorf("only Ed25519 keys supported, got: %s", keyTypeStr)
	}

	var pubKeyLen uint32
	if err := binary.Read(pubKeyReader, binary.BigEndian, &pubKeyLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read public key length: %w", err)
	}

	publicKeyBytes := make([]byte, pubKeyLen)
	if _, err := io.ReadFull(pubKeyReader, publicKeyBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	if len(publicKeyBytes) != 32 {
		return nil, nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(publicKeyBytes))
	}

	// Extract signature
	sigReader := bytes.NewReader(sshSig.Signature)

	var sigTypeLen uint32
	if err := binary.Read(sigReader, binary.BigEndian, &sigTypeLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature type length: %w", err)
	}

	sigType := make([]byte, sigTypeLen)
	if _, err := io.ReadFull(sigReader, sigType); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature type: %w", err)
	}

	sigTypeStr := string(sigType)
	if sigTypeStr != "ssh-ed25519" && sigTypeStr != "sk-ssh-ed25519@openssh.com" {
		return nil, nil, fmt.Errorf("signature type mismatch: %s", sigTypeStr)
	}

	var sigLen uint32
	if err := binary.Read(sigReader, binary.BigEndian, &sigLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature length: %w", err)
	}

	signature := make([]byte, sigLen)
	if _, err := io.ReadFull(sigReader, signature); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature: %w", err)
	}

	if len(signature) != 64 {
		return nil, nil, fmt.Errorf("invalid Ed25519 signature length: %d", len(signature))
	}

	return ed25519.PublicKey(publicKeyBytes), signature, nil
}
