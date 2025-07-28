package checksignature

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type SignatureStatus string

const (
	ValidSignature                SignatureStatus = "valid"
	ExpiredButValidSignature      SignatureStatus = "valid-but-expired-key"
	InvalidSignature              SignatureStatus = "invalid"
	MissingPublicKey              SignatureStatus = "signed-but-missing-key"
	ValidSignatureButNotCertified SignatureStatus = "valid-but-not-certified"
	UnsignedCommit                SignatureStatus = "unsigned"
	VerificationError             SignatureStatus = "error"
	EmailNotMatched               SignatureStatus = "signed-but-untrusted-email"
)

type SignatureCheckResult struct {
	CommitSHA string
	Status    string
	Output    string
	Err       error
}

type LocalCheckConfig struct {
	CommitsToCheck         int
	AcceptExpiredKeys      bool
	AcceptUnsignedCommits  bool
	AcceptUntrustedSigners bool
	AcceptUncertifiedKeys  bool
	AcceptMissingPublicKey bool
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

func extractEmailsFromSignatureOutput(output string) (signerEmail string, authorEmail string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Good signature from") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 && end > start {
				signerEmail = line[start+1 : end]
			}
		}
		if strings.HasPrefix(line, "Author:") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 && end > start {
				authorEmail = line[start+1 : end]
			}
		}
	}
	return
}

func extractAuthorEmail(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "author ") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 && end > start {
				return line[start+1 : end]
			}
		}
	}
	return ""
}

func checkEmailMismatch(commitData []byte, signerEmail string) bool {
	content := string(commitData)
	commitAuthorEmail := extractAuthorEmail(content)

	if commitAuthorEmail != "" && signerEmail != "" {
		return commitAuthorEmail != signerEmail
	}
	return false
}

func classifySignature(output string) SignatureStatus {
	signerEmail, authorEmail := extractEmailsFromSignatureOutput(output)

	switch {
	case strings.Contains(output, "Good") && strings.Contains(output, "expired"):
		return ExpiredButValidSignature

	case strings.Contains(output, "Good") &&
		strings.Contains(output, "There is no indication that the signature belongs to the owner"):
		return ValidSignatureButNotCertified

	case strings.Contains(output, "Good") && (strings.Contains(output, "ED25519") || strings.Contains(output, "RSA key")):
		if signerEmail != "" && authorEmail != "" && signerEmail != authorEmail {
			return EmailNotMatched
		}
		return ValidSignature

	case strings.Contains(output, "Can't check signature: No public key"):
		return MissingPublicKey

	case strings.Contains(output, "BAD signature") ||
		strings.Contains(output, "Can't check signature"):
		return InvalidSignature

	default:
		return UnsignedCommit
	}
}

// PGP signature verification
func verifyPGPSignature(raw []byte) (SignatureStatus, string, error) {
	content := string(raw)

	if !strings.Contains(content, "gpgsig -----BEGIN PGP SIGNATURE-----") {
		return UnsignedCommit, "No PGP signature found", nil
	}

	lines := strings.Split(content, "\n")

	sigStart := -1
	sigEnd := -1

	for i, line := range lines {
		if strings.HasPrefix(line, "gpgsig -----BEGIN PGP SIGNATURE-----") {
			sigStart = i
		}
		if strings.HasPrefix(line, " -----END PGP SIGNATURE-----") {
			sigEnd = i
			break
		}
	}

	if sigStart == -1 || sigEnd == -1 {
		return VerificationError, "Wrong PGP signature format", nil
	}

	var sigLines []string
	for i := sigStart; i <= sigEnd; i++ {
		line := lines[i]
		if strings.HasPrefix(line, "gpgsig ") {
			sigContent := strings.TrimPrefix(line, "gpgsig ")
			sigLines = append(sigLines, sigContent)
		} else if strings.HasPrefix(line, " ") {
			sigContent := strings.TrimPrefix(line, " ")
			sigLines = append(sigLines, sigContent)
		}
	}

	signature := strings.Join(sigLines, "\n")
	publicKey, keyID, err := extractPGPPublicKeyFromSignature(signature)

	var keyImported bool
	if err == nil && publicKey != "" {
		if importErr := importPGPKeyDirectly(publicKey); importErr == nil {
			keyImported = true
		}
	}

	var payloadLines []string
	for i, line := range lines {
		if i < sigStart || i > sigEnd {
			payloadLines = append(payloadLines, line)
		}
	}

	for len(payloadLines) > 0 && payloadLines[len(payloadLines)-1] == "" {
		payloadLines = payloadLines[:len(payloadLines)-1]
	}

	payload := strings.Join(payloadLines, "\n") + "\n"
	payloadBytes := []byte(payload)

	sigFile, err := os.CreateTemp("", "*.sig")
	if err != nil {
		return VerificationError, "", err
	}
	defer os.Remove(sigFile.Name())
	defer sigFile.Close()

	payloadFile, err := os.CreateTemp("", "*.txt")
	if err != nil {
		return VerificationError, "", err
	}
	defer os.Remove(payloadFile.Name())
	defer payloadFile.Close()

	if _, err := sigFile.Write([]byte(signature)); err != nil {
		return VerificationError, "", err
	}
	sigFile.Close()

	if _, err := payloadFile.Write(payloadBytes); err != nil {
		return VerificationError, "", err
	}
	payloadFile.Close()

	cmd := exec.Command("gpg", "--verify", sigFile.Name(), payloadFile.Name())
	output, err := cmd.CombinedOutput()
	status := classifySignature(string(output))

	if status == ValidSignature {
		signerEmail, _ := extractEmailsFromSignatureOutput(string(output))
		if checkEmailMismatch(raw, signerEmail) {
			return EmailNotMatched, string(output), err
		}
	}

	if status == MissingPublicKey && keyImported {
		return MissingPublicKey, fmt.Sprintf("PGP signature found with key ID %s, but verification failed: %s", keyID, string(output)), err
	}

	return status, string(output), err
}

func extractPGPPublicKeyFromSignature(signature string) (publicKey string, keyID string, err error) {
	cmd := exec.Command("gpg", "--list-packets")
	cmd.Stdin = strings.NewReader(signature)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to parse PGP signature: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "keyid") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "keyid" && i+1 < len(parts) {
					keyID = parts[i+1]
					break
				}
			}
		}
	}

	if keyID == "" {
		return "", "", fmt.Errorf("could not extract key ID from signature")
	}

	publicKey, err = fetchPGPKeyFromKeyserver(keyID)
	if err != nil {
		return "", keyID, fmt.Errorf("could not fetch key %s from keyservers: %v", keyID, err)
	}

	return publicKey, keyID, nil
}

func fetchPGPKeyFromKeyserver(keyID string) (string, error) {
	keyservers := []string{
		"keys.openpgp.org",
		"keyserver.ubuntu.com",
	}

	for _, server := range keyservers {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "gpg", "--keyserver", server, "--recv-keys", keyID)
		if err := cmd.Run(); err == nil {
			exportCtx, exportCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer exportCancel()
			exportCmd := exec.CommandContext(exportCtx, "gpg", "--armor", "--export", keyID)
			output, exportErr := exportCmd.Output()
			if exportErr == nil {
				return string(output), nil
			}
		}
	}

	return "", fmt.Errorf("key not found on any keyserver")
}

func importPGPKeyDirectly(publicKey string) error {
	cmd := exec.Command("gpg", "--import")
	cmd.Stdin = strings.NewReader(publicKey)
	return cmd.Run()
}

// SSH signature verification
func verifySSHSignature(raw []byte) (SignatureStatus, string, error) {
	content := string(raw)

	if !strings.Contains(content, "gpgsig -----BEGIN SSH SIGNATURE-----") {
		return UnsignedCommit, "No SSH signature found", nil
	}

	sshSig, err := extractSSHSignatureData(content)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to parse SSH signature: %v", err), err
	}

	keyType, err := getSSHKeyType(sshSig.PublicKey)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to determine key type: %v", err), err
	}

	switch keyType {
	case "ssh-ed25519":
		return verifyEd25519SSH(sshSig, content)
	default:
		return ValidSignatureButNotCertified,
			fmt.Sprintf("SSH signature with %s key found but verification not implemented", keyType), nil
	}
}

func extractSSHSignatureData(raw string) (*SSHSignatureData, error) {
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

	return &SSHSignatureData{
		ArmoredSignature: armored,
		SignatureBlob:    blob,
		Namespace:        string(namespace),
		HashAlgorithm:    string(hashAlg),
		PublicKey:        pkBlob,
		Signature:        sigBlob,
		IdentityComment:  string(comment),
	}, nil
}

func getSSHKeyType(publicKeyBlob []byte) (string, error) {
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

func verifyEd25519SSH(sshSig *SSHSignatureData, content string) (SignatureStatus, string, error) {
	publicKey, signature, err := extractKeyAndSignatureFromSSH(sshSig)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to extract Ed25519 data: %v", err), err
	}

	signedPayload, err := computeSSHSignedPayload(content, sshSig.Namespace, sshSig.HashAlgorithm)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to compute payload: %v", err), err
	}

	valid := ed25519.Verify(publicKey, signedPayload, signature)

	if valid {
		authorEmail := extractAuthorEmail(content)

		if sshSig.IdentityComment != "" && authorEmail != "" {
			if sshSig.IdentityComment != authorEmail {
				return EmailNotMatched,
					fmt.Sprintf("Valid Ed25519 SSH signature but identity mismatch: signature=%s, author=%s",
						sshSig.IdentityComment, authorEmail), nil
			}
		}

		return ValidSignature, fmt.Sprintf("Valid Ed25519 SSH signature for %s", authorEmail), nil
	}

	return InvalidSignature, "Ed25519 SSH signature verification failed", nil
}

func extractKeyAndSignatureFromSSH(sshSig *SSHSignatureData) (ed25519.PublicKey, []byte, error) {
	pubKeyReader := bytes.NewReader(sshSig.PublicKey)

	var keyTypeLen uint32
	if err := binary.Read(pubKeyReader, binary.BigEndian, &keyTypeLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read key type length: %w", err)
	}

	keyType := make([]byte, keyTypeLen)
	if _, err := io.ReadFull(pubKeyReader, keyType); err != nil {
		return nil, nil, fmt.Errorf("failed to read key type: %w", err)
	}

	if string(keyType) != "ssh-ed25519" {
		return nil, nil, fmt.Errorf("only Ed25519 keys supported, got: %s", string(keyType))
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

	sigReader := bytes.NewReader(sshSig.Signature)

	var sigTypeLen uint32
	if err := binary.Read(sigReader, binary.BigEndian, &sigTypeLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature type length: %w", err)
	}

	sigType := make([]byte, sigTypeLen)
	if _, err := io.ReadFull(sigReader, sigType); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature type: %w", err)
	}

	if string(sigType) != "ssh-ed25519" {
		return nil, nil, fmt.Errorf("signature type mismatch: %s", string(sigType))
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

func computeSSHSignedPayload(content, namespace, hashAlgorithm string) ([]byte, error) {
	cleanCommit := removeSSHSignatureFromCommit(content)

	cleanCommit = strings.TrimSuffix(cleanCommit, "\n")

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

func removeSSHSignatureFromCommit(raw string) string {
	var b strings.Builder
	inSig := false

	for _, line := range strings.Split(raw, "\n") {
		switch {
		case strings.HasPrefix(line, "gpgsig "):
			inSig = true
			continue
		case inSig && strings.HasPrefix(line, " "):
			continue
		case inSig:
			inSig = false
		}

		b.WriteString(line)
		b.WriteByte('\n')
	}

	if b.Len() == 0 || b.String()[b.Len()-1] != '\n' {
		b.WriteByte('\n')
	}
	return b.String()
}

func CheckSignatureLocal(repoPath, sha string, config LocalCheckConfig) ([]SignatureCheckResult, error) {
	repoURL := fmt.Sprintf("https://github.com/%s.git", repoPath)
	tmpDir, err := os.MkdirTemp("", "repo-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if out, err := exec.Command("git", "clone", repoURL, tmpDir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to clone: %v\n%s", err, out)
	}

	var cmd *exec.Cmd
	if config.CommitsToCheck > 0 {
		cmd = exec.Command("git", "rev-list", "-n", fmt.Sprintf("%d", config.CommitsToCheck), sha)
	} else {
		cmd = exec.Command("git", "rev-list", sha)
	}

	cmd.Dir = tmpDir
	shaListRaw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list commits: %v", err)
	}
	shas := strings.Split(strings.TrimSpace(string(shaListRaw)), "\n")

	var results []SignatureCheckResult

	for _, s := range shas {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		catCmd := exec.CommandContext(ctx, "git", "cat-file", "commit", s)
		catCmd.Dir = tmpDir
		catOut, catErr := catCmd.CombinedOutput()

		if catErr != nil {
			results = append(results, SignatureCheckResult{
				CommitSHA: s,
				Status:    string(VerificationError),
				Output:    string(catOut),
				Err:       catErr,
			})
			continue
		}

		status, output, err := verifyPGPSignature(catOut)

		if status == UnsignedCommit || status == MissingPublicKey {

			sshStatus, sshOutput, sshErr := verifySSHSignature(catOut)

			if sshStatus == ValidSignature {
				status = sshStatus
				output = sshOutput
				err = sshErr
			} else if sshStatus != UnsignedCommit {
				status = sshStatus
				output = sshOutput
				err = sshErr
			}
		}

		results = append(results, SignatureCheckResult{
			CommitSHA: s,
			Status:    string(status),
			Output:    output,
			Err:       err,
		})
	}

	return results, nil
}
