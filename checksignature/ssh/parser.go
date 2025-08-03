package ssh

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
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
