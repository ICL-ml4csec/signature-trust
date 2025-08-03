package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/utils"
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

// extractECDSAKeyAndSignature extracts ECDSA public key and signature components from SSH signature data
func extractECDSAKeyAndSignature(sshSig *types.SSHSignatureData) (*ecdsa.PublicKey, *big.Int, *big.Int, error) {
	pubKeyReader := bytes.NewReader(sshSig.PublicKey)

	// Skip key type
	var keyTypeLen uint32
	binary.Read(pubKeyReader, binary.BigEndian, &keyTypeLen)
	pubKeyReader.Seek(int64(keyTypeLen), io.SeekCurrent)

	// Skip curve name
	var curveNameLen uint32
	binary.Read(pubKeyReader, binary.BigEndian, &curveNameLen)
	pubKeyReader.Seek(int64(curveNameLen), io.SeekCurrent)

	// Read public key point
	var pubKeyPointLen uint32
	if err := binary.Read(pubKeyReader, binary.BigEndian, &pubKeyPointLen); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read public key point length: %w", err)
	}

	pubKeyPoint := make([]byte, pubKeyPointLen)
	if _, err := io.ReadFull(pubKeyReader, pubKeyPoint); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read public key point: %w", err)
	}

	if len(pubKeyPoint) != 65 || pubKeyPoint[0] != 0x04 {
		return nil, nil, nil, fmt.Errorf("invalid ECDSA public key point format")
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(pubKeyPoint[1:33])
	y := new(big.Int).SetBytes(pubKeyPoint[33:65])

	if !curve.IsOnCurve(x, y) {
		return nil, nil, nil, fmt.Errorf("public key point not on P-256 curve")
	}

	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Extract signature components
	sigReader := bytes.NewReader(sshSig.Signature)

	// Skip signature type
	var sigTypeLen uint32
	binary.Read(sigReader, binary.BigEndian, &sigTypeLen)
	sigReader.Seek(int64(sigTypeLen), io.SeekCurrent)

	// Read signature blob
	var sigLen uint32
	binary.Read(sigReader, binary.BigEndian, &sigLen)

	signature := make([]byte, sigLen)
	io.ReadFull(sigReader, signature)

	// Parse signature components (r, s)
	sigReader = bytes.NewReader(signature)

	var rLen uint32
	binary.Read(sigReader, binary.BigEndian, &rLen)
	rBytes := make([]byte, rLen)
	io.ReadFull(sigReader, rBytes)

	var sLen uint32
	binary.Read(sigReader, binary.BigEndian, &sLen)
	sBytes := make([]byte, sLen)
	io.ReadFull(sigReader, sBytes)

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	return publicKey, r, s, nil
}
