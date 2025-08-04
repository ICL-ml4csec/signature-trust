package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
)

// ExtractSignatureData parses SSH signature from commit content
func ExtractSignatureData(raw string) (*types.SSHSignatureData, error) {
	var armour []string
	inBlock := false
	for _, l := range strings.Split(raw, "\n") {
		switch {
		case strings.HasPrefix(l, "gpgsig -----BEGIN SSH SIGNATURE-----"):
			armour = append(armour, strings.TrimPrefix(l, "gpgsig "))
			inBlock = true
		case inBlock && strings.HasPrefix(l, " "):
			armour = append(armour, strings.TrimSpace(l))
		case inBlock && strings.HasPrefix(l, "-----END"):
			armour = append(armour, l[1:])
			inBlock = false
		}
	}
	if len(armour) == 0 {
		return nil, fmt.Errorf("SSH signature block not found")
	}
	armored := strings.Join(armour, "\n")

	var b64 string
	for _, l := range armour {
		if !strings.HasPrefix(l, "-----") {
			b64 += strings.TrimSpace(l)
		}
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}
	if len(blob) < 10 || string(blob[:6]) != "SSHSIG" {
		return nil, fmt.Errorf("invalid SSH signature magic")
	}
	off := 6
	off += 4

	read := func() ([]byte, error) {
		if len(blob) < off+4 {
			return nil, fmt.Errorf("truncated")
		}
		l := binary.BigEndian.Uint32(blob[off:])
		off += 4
		if len(blob) < off+int(l) {
			return nil, fmt.Errorf("truncated")
		}
		s := blob[off : off+int(l)]
		off += int(l)
		return s, nil
	}

	pkBlob, _ := read()
	namespace, _ := read()
	_, _ = read()
	hashAlg, _ := read()
	sigBlob, _ := read()

	comment, _ := func() ([]byte, error) {
		if off < len(blob) {
			return read()
		}
		return []byte{}, nil
	}()

	return &types.SSHSignatureData{
		ArmoredSignature: armored,
		SignatureBlob:    blob,
		Namespace:        string(namespace),
		HashAlgorithm:    string(hashAlg),
		PublicKey:        pkBlob,
		Signature:        sigBlob,
		IdentityComment:  string(comment),
	}, nil
}

// GetKeyType extracts the SSH key type from public key blob
func GetKeyType(publicKeyBlob []byte) (string, error) {
	reader := bytes.NewReader(publicKeyBlob)

	var keyTypeLen uint32
	if err := binary.Read(reader, binary.BigEndian, &keyTypeLen); err != nil {
		return "", err
	}

	keyType := make([]byte, keyTypeLen)
	if _, err := io.ReadFull(reader, keyType); err != nil {
		return "", err
	}

	return string(keyType), nil
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
