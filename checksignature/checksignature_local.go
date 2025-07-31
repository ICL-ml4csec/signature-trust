package checksignature

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
	"github.com/ICL-ml4csec/msc-hmj24/client"
	"github.com/ICL-ml4csec/msc-hmj24/trustpolicies"
)

type SignatureStatus string

const (
	ValidSignature                 SignatureStatus = "valid"
	ExpiredButValidSignature       SignatureStatus = "valid-but-expired-key"
	InvalidSignature               SignatureStatus = "invalid"
	MissingPublicKey               SignatureStatus = "signed-but-missing-key"
	ValidSignatureButNotCertified  SignatureStatus = "valid-but-not-certified"
	ValidSignatureButNotAuthorized SignatureStatus = "valid-but-not-authorized"
	UnsignedCommit                 SignatureStatus = "unsigned"
	VerificationError              SignatureStatus = "error"
	EmailNotMatched                SignatureStatus = "signed-but-untrusted-email"
	GitHubAutomatedSignature       SignatureStatus = "github-automated-signature"
)

type SignatureCheckResult struct {
	CommitSHA string
	Status    string
	Output    string
	Err       error
}

type LocalCheckConfig struct {
	Branch                       string
	Token                        string
	Repo                         string
	CommitsToCheck               int
	OldestSHA                    string
	AcceptExpiredKeys            bool
	AcceptUnsignedCommits        bool
	AcceptUntrustedSigners       bool
	AcceptUncertifiedKeys        bool
	AcceptMissingPublicKey       bool
	AcceptGitHubAutomated        bool
	AcceptUnauthorizedSignatures bool
	TimeCutoff                   *time.Time
	KeyCreationCutoff            *time.Time
}

type GitHubGPGKey struct {
	ID           int         `json:"id"`
	PrimaryKeyID interface{} `json:"primary_key_id"`
	KeyID        string      `json:"key_id"`
	PublicKey    string      `json:"public_key"`
	Emails       []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	} `json:"emails"`
	Subkeys []struct {
		ID                int         `json:"id"`
		PrimaryKeyID      interface{} `json:"primary_key_id"`
		KeyID             string      `json:"key_id"`
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

type SSHSignatureData struct {
	ArmoredSignature string
	SignatureBlob    []byte
	Namespace        string
	HashAlgorithm    string
	PublicKey        []byte
	Signature        []byte
	IdentityComment  string
}

type GitHubKey struct {
	ID          int       `json:"id"`
	Key         string    `json:"key"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
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

func isGitHubAutomatedCommit(gpgOutput string, content string, sshSig *SSHSignatureData) bool {
	authorEmail := extractAuthorEmail(content)
	if authorEmail == "noreply@github.com" ||
		strings.HasSuffix(authorEmail, "@users.noreply.github.com") {
		return true
	}

	if gpgOutput != "" {
		if strings.Contains(gpgOutput, "noreply@github.com") ||
			strings.Contains(gpgOutput, "GitHub <noreply@github.com>") {
			return true
		}
	}

	if sshSig != nil {
		if sshSig.IdentityComment == "noreply@github.com" ||
			strings.HasSuffix(sshSig.IdentityComment, "@users.noreply.github.com") {
			return true
		}
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
func verifyPGPSignature(raw []byte, sha string, config LocalCheckConfig) (SignatureStatus, string, error) {
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

	if keyID != "" {
		createdAt, err := trustpolicies.GetPGPKeyCreationTime(keyID)
		if err == nil {
			if config.KeyCreationCutoff != nil && createdAt.After(*config.KeyCreationCutoff) {
				return InvalidSignature, fmt.Sprintf("Key %s created too recently (%s)", keyID, createdAt.Format(time.RFC3339)), nil
			}
		}
	}

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

	if isGitHubAutomatedCommit(string(output), content, nil) {
		return GitHubAutomatedSignature, string(output), err
	}

	if status == ValidSignature {
		signerEmail, _ := extractEmailsFromSignatureOutput(string(output))
		if checkEmailMismatch(raw, signerEmail) {
			return EmailNotMatched, string(output), err
		}

		if config.Token != "" && config.Repo != "" && sha != "" {
			authorized, authErr := checkGPGKeyAuthorization(keyID, config.Repo, sha, config.Token)
			if authErr != nil {
				fmt.Printf("Warning: Could not verify GPG key authorization: %v\n", authErr)
			} else if !authorized {
				return ValidSignatureButNotAuthorized,
					fmt.Sprintf("Valid GPG signature with key %s, but key is not registered on the commit author's GitHub account", keyID), err
			}
		}
	}

	if status == MissingPublicKey && keyImported {
		return MissingPublicKey, fmt.Sprintf("PGP signature found with key ID %s, but verification failed: %s", keyID, string(output)), err
	}

	return status, string(output), err
}

func interfaceToString(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func checkGPGKeyAuthorization(keyID, repo, commitSHA, token string) (bool, error) {
	if token == "" {
		return true, fmt.Errorf("no GitHub token provided, skipping GPG key authorization")
	}

	username, err := GetCommitContributor(repo, commitSHA, token)
	if err != nil {
		return false, fmt.Errorf("failed to get commit contributor: %v", err)
	}

	gpgKeys, err := GetUserGPGKeys(username, token)
	if err != nil {
		return false, fmt.Errorf("failed to get user GPG keys: %v", err)
	}

	for _, key := range gpgKeys {
		primaryKeyID := interfaceToString(key.PrimaryKeyID)
		if normalizeKeyID(key.KeyID) == normalizeKeyID(keyID) ||
			normalizeKeyID(primaryKeyID) == normalizeKeyID(keyID) {
			return true, nil
		}

		for _, subkey := range key.Subkeys {
			subkeyPrimaryID := interfaceToString(subkey.PrimaryKeyID)
			if subkey.CanSign && (normalizeKeyID(subkey.KeyID) == normalizeKeyID(keyID) ||
				normalizeKeyID(subkeyPrimaryID) == normalizeKeyID(keyID)) {
				return true, nil
			}
		}
	}

	return false, nil
}

func GetUserGPGKeys(username, token string) ([]GitHubGPGKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/gpg_keys", username)

	resp, err := client.DoGet(url, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []GitHubGPGKey{}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var keys []GitHubGPGKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	return keys, nil
}

func normalizeKeyID(keyID string) string {
	keyID = strings.TrimPrefix(keyID, "0x")
	keyID = strings.TrimPrefix(keyID, "0X")
	keyID = strings.ToUpper(keyID)

	if len(keyID) > 16 {
		keyID = keyID[len(keyID)-16:]
	}

	return keyID
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
func verifySSHSignature(raw []byte, sha string, config LocalCheckConfig) (SignatureStatus, string, error) {
	content := string(raw)

	if !strings.Contains(content, "gpgsig -----BEGIN SSH SIGNATURE-----") {
		return UnsignedCommit, "No SSH signature found", nil
	}

	sshSig, err := extractSSHSignatureData(content)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to parse SSH signature: %v", err), err
	}

	if config.KeyCreationCutoff != nil && config.Token != "" {
		ok, createdAt, err := checkSSHKeyAge(sshSig.PublicKey, config.Repo, sha, config.Token, config.KeyCreationCutoff)
		if err != nil {
			fingerprint, fpErr := computeSSHFingerprint(sshSig.PublicKey)
			if fpErr != nil {
				fingerprint = "unknown"
			}
			return MissingPublicKey, fmt.Sprintf("SSH signing key %s not found in GitHub account: %v", fingerprint, err), nil
		}
		if !ok {
			fingerprint, fpErr := computeSSHFingerprint(sshSig.PublicKey)
			if fpErr != nil {
				fingerprint = "unknown"
			}
			return InvalidSignature, fmt.Sprintf("Key %s created too recently (%s)", fingerprint, createdAt.Format(time.RFC3339)), nil
		}
	}

	keyType, err := getSSHKeyType(sshSig.PublicKey)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to determine key type: %v", err), err
	}

	if isGitHubAutomatedCommit("", content, sshSig) {
		return GitHubAutomatedSignature, "GitHub automated SSH signature detected", nil
	}

	var status SignatureStatus
	var output string
	switch keyType {
	case "ssh-ed25519":
		status, output, err = verifyEd25519SSH(sshSig, content, false)
	case "sk-ssh-ed25519@openssh.com":
		status, output, err = verifyEd25519SSH(sshSig, content, true)
	case "ecdsa-sha2-nistp256":
		status, output, err = verifyECDSAP256SSH(sshSig, content, false)
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		status, output, err = verifyECDSAP256SSH(sshSig, content, true)
	case "ssh-rsa":
		return ValidSignatureButNotCertified, "SSH-RSA signatures are not supported for commit signing (deprecated by GitHub for security reasons). Use Ed25519: ssh-keygen -t ed25519", nil
	case "ssh-dss":
		return InvalidSignature, "SSH-DSS keys are cryptographically broken and not supported", nil
	case "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return ValidSignatureButNotCertified,
			fmt.Sprintf("ECDSA %s curves not supported. GitHub only supports nistp256 for ECDSA. Consider Ed25519 instead.",
				strings.TrimPrefix(keyType, "ecdsa-sha2-")), nil
	default:
		return VerificationError, fmt.Sprintf("Unknown SSH key type: %s", keyType), nil
	}

	if status == ValidSignature {
		signerIdentity := sshSig.IdentityComment

		isSecurityKey := strings.Contains(keyType, "sk-")

		if !isSecurityKey && signerIdentity != "" {
			if checkEmailMismatch(raw, signerIdentity) {
				return EmailNotMatched, fmt.Sprintf("SSH signature identity mismatch: signature=%s, commit author=%s",
					signerIdentity, extractAuthorEmail(content)), err
			}
		}
	}

	return status, output, err
}

func verifyEd25519SSH(sshSig *SSHSignatureData, content string, isSecurityKey bool) (SignatureStatus, string, error) {
	keyTypeDesc := "Ed25519"
	if isSecurityKey {
		keyTypeDesc = "security key Ed25519"
	}

	publicKey, signature, err := extractEd25519KeyAndSignatureFromSSH(sshSig)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to extract %s data: %v", keyTypeDesc, err), err
	}

	signedPayload, err := computeSSHSignedPayload(content, sshSig.Namespace, sshSig.HashAlgorithm)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to compute payload: %v", err), err
	}

	valid := ed25519.Verify(publicKey, signedPayload, signature)

	if valid {
		authorEmail := extractAuthorEmail(content)
		return ValidSignature, fmt.Sprintf("Valid %s SSH signature for %s", keyTypeDesc, authorEmail), nil
	}

	return InvalidSignature, fmt.Sprintf("%s SSH signature verification failed", keyTypeDesc), nil
}

func verifyECDSAP256SSH(sshSig *SSHSignatureData, content string, isSecurityKey bool) (SignatureStatus, string, error) {
	keyTypeDesc := "ECDSA P-256"
	if isSecurityKey {
		keyTypeDesc = "security key ECDSA P-256"
	}

	publicKey, r, s, err := extractECDSAKeyAndSignatureFromSSH(sshSig)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to extract %s data: %v", keyTypeDesc, err), err
	}

	signedPayload, err := computeSSHSignedPayload(content, sshSig.Namespace, sshSig.HashAlgorithm)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to compute payload: %v", err), err
	}

	hash := sha256.Sum256(signedPayload)
	valid := ecdsa.Verify(publicKey, hash[:], r, s)

	if valid {
		authorEmail := extractAuthorEmail(content)
		return ValidSignature, fmt.Sprintf("Valid %s SSH signature for %s", keyTypeDesc, authorEmail), nil
	}

	return InvalidSignature, fmt.Sprintf("%s SSH signature verification failed", keyTypeDesc), nil
}

func extractECDSAKeyAndSignatureFromSSH(sshSig *SSHSignatureData) (*ecdsa.PublicKey, *big.Int, *big.Int, error) {
	pubKeyReader := bytes.NewReader(sshSig.PublicKey)

	var keyTypeLen uint32
	binary.Read(pubKeyReader, binary.BigEndian, &keyTypeLen)
	pubKeyReader.Seek(int64(keyTypeLen), io.SeekCurrent)

	var curveNameLen uint32
	binary.Read(pubKeyReader, binary.BigEndian, &curveNameLen)
	pubKeyReader.Seek(int64(curveNameLen), io.SeekCurrent)

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

	sigReader := bytes.NewReader(sshSig.Signature)

	var sigTypeLen uint32
	binary.Read(sigReader, binary.BigEndian, &sigTypeLen)
	sigReader.Seek(int64(sigTypeLen), io.SeekCurrent)

	var sigLen uint32
	binary.Read(sigReader, binary.BigEndian, &sigLen)

	signature := make([]byte, sigLen)
	io.ReadFull(sigReader, signature)

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

func computeSSHFingerprint(pubKeyBlob []byte) (string, error) {
	reader := bytes.NewReader(pubKeyBlob)

	var keyTypeLen uint32
	if err := binary.Read(reader, binary.BigEndian, &keyTypeLen); err != nil {
		return "", err
	}

	keyType := make([]byte, keyTypeLen)
	if _, err := io.ReadFull(reader, keyType); err != nil {
		return "", err
	}

	h := sha256.Sum256(pubKeyBlob)
	fp := base64.StdEncoding.EncodeToString(h[:])

	return fmt.Sprintf("SHA256:%s", strings.TrimRight(fp, "=")), nil
}

type KeyAnalysisResult struct {
	Username        string
	KeyCount        int
	RecentKeys      []GitHubUserKey
	OldKeys         []GitHubUserKey
	TotalSuspicious int
}

type GitHubUserKey struct {
	ID          int       `json:"id"`
	Key         string    `json:"key"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
	Title       string    `json:"title"`
}

func checkSSHKeyAge(pubKeyBlob []byte, repo, commitSHA, token string, cutoff *time.Time) (bool, *time.Time, error) {
	fingerprint, err := computeSSHFingerprint(pubKeyBlob)
	if err != nil {
		return false, nil, err
	}

	username, err := GetCommitContributor(repo, commitSHA, token)
	if err != nil {
		return false, nil, err
	}

	keys, err := GetUserSSHSigningKeys(username, token)
	if err != nil {
		return false, nil, err
	}

	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			if cutoff != nil && key.CreatedAt.After(*cutoff) {
				return false, &key.CreatedAt, nil
			}
			return true, &key.CreatedAt, nil
		}
	}

	return false, nil, fmt.Errorf("key fingerprint not found in GitHub or local database")
}

func GetUserSSHSigningKeys(username, token string) ([]GitHubUserKey, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/ssh_signing_keys", username)
	return FetchUserKeys(url, token)
}

func FetchUserKeys(url, token string) ([]GitHubUserKey, error) {
	resp, err := client.DoGet(url, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []GitHubUserKey{}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var keys []GitHubUserKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	for i := range keys {
		if keys[i].Key != "" {
			fingerprint, err := computeFingerprintFromSSHKey(keys[i].Key)
			if err != nil {
				continue
			}
			keys[i].Fingerprint = fingerprint
		}
	}

	return keys, nil
}

func computeFingerprintFromSSHKey(sshKey string) (string, error) {
	parts := strings.Fields(sshKey)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid SSH key format")
	}

	keyData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode SSH key: %v", err)
	}

	h := sha256.Sum256(keyData)
	fp := base64.StdEncoding.EncodeToString(h[:])

	return fmt.Sprintf("SHA256:%s", strings.TrimRight(fp, "=")), nil
}

func GetCommitContributor(repo, commitSHA, token string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, commitSHA)

	resp, err := client.DoGet(url, token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var commit struct {
		Author struct {
			Login string `json:"login"`
		} `json:"author"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&commit); err != nil {
		return "", err
	}

	if commit.Author.Login == "" {
		return "", fmt.Errorf("no GitHub user associated with commit")
	}

	return commit.Author.Login, nil
}

func extractEd25519KeyAndSignatureFromSSH(sshSig *SSHSignatureData) (ed25519.PublicKey, []byte, error) {
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
	lineCount := 0

	for _, line := range strings.Split(raw, "\n") {
		lineCount++
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

	result := b.String()

	return result
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

	branchToUse := config.Branch
	checkBranchCmd := exec.Command("git", "rev-parse", "--verify", "origin/"+branchToUse)
	checkBranchCmd.Dir = tmpDir
	if err := checkBranchCmd.Run(); err != nil {
		branchToUse = helpers.GetDefaultBranch(tmpDir)
	}

	var revArgs []string
	if config.TimeCutoff != nil {
		cutoffSHA, err := trustpolicies.GetSHAFromTime(tmpDir, branchToUse, *config.TimeCutoff)
		if err != nil {
			return nil, fmt.Errorf("failed to get SHA from time: %v", err)
		}
		if cutoffSHA != "" {
			revArgs = []string{"git", "rev-list", "origin/" + branchToUse, "^" + cutoffSHA}
		} else {
			fmt.Printf("No commits older than %s on branch %s, checking all commits\n",
				config.TimeCutoff.Format(time.RFC3339), branchToUse)
			revArgs = []string{"git", "rev-list", "origin/" + branchToUse}
		}
	} else if config.OldestSHA != "" {
		revArgs = []string{"git", "rev-list", "origin/" + branchToUse, "^" + config.OldestSHA}
	} else if config.CommitsToCheck > 0 {
		revArgs = []string{"git", "rev-list", "-n", fmt.Sprint(config.CommitsToCheck), "origin/" + branchToUse}
	} else {
		revArgs = []string{"git", "rev-list", "origin/" + branchToUse}
	}

	cmd := exec.Command(revArgs[0], revArgs[1:]...)
	cmd.Dir = tmpDir
	shaListRaw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list commits on branch %s: %v", branchToUse, err)
	}

	shaList := strings.TrimSpace(string(shaListRaw))
	if shaList == "" {
		return []SignatureCheckResult{}, nil
	}

	shas := strings.Split(shaList, "\n")

	var results []SignatureCheckResult

	for _, s := range shas {
		if strings.TrimSpace(s) == "" {
			continue
		}

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

		hasSSH := strings.Contains(string(catOut), "BEGIN SSH SIGNATURE")
		hasPGP := strings.Contains(string(catOut), "BEGIN PGP SIGNATURE")

		var status SignatureStatus
		var output string
		var err error

		if hasPGP {
			status, output, err = verifyPGPSignature(catOut, s, config)
		}

		if hasSSH {
			sshStatus, sshOutput, sshErr := verifySSHSignature(catOut, s, config)

			if hasPGP {
				if status == InvalidSignature || sshStatus == InvalidSignature {
					if status == InvalidSignature {
					} else {
						status = sshStatus
						output = sshOutput
						err = sshErr
					}
				} else if sshStatus == ValidSignature && status != ValidSignature {
				} else if status == ValidSignature && sshStatus != ValidSignature {
					status = sshStatus
					output = sshOutput
					err = sshErr
				}
			} else {
				status = sshStatus
				output = sshOutput
				err = sshErr
			}
		}

		if !hasPGP && !hasSSH {
			status = UnsignedCommit
			output = "No signature found"
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
