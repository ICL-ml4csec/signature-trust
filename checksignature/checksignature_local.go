package checksignature

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
		"keyserver.ubuntu.com",
		"keys.openpgp.org",
		"pgp.mit.edu",
	}

	for _, server := range keyservers {
		cmd := exec.Command("gpg", "--keyserver", server, "--recv-keys", keyID)
		if err := cmd.Run(); err == nil {
			exportCmd := exec.Command("gpg", "--armor", "--export", keyID)
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

func verifySSHSignature(raw []byte) (SignatureStatus, string, error) {
	content := string(raw)

	if !strings.Contains(content, "gpgsig -----BEGIN SSH SIGNATURE-----") {
		return UnsignedCommit, "No SSH signature found", nil
	}

	authorEmail := extractAuthorEmail(content)

	sshSig, err := extractSSHSignatureData(content)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to parse SSH signature: %v", err), err
	}

	publicKey, err := extractPublicKeyFromSSHSignature(sshSig.SignatureBlob)
	if err != nil {
		return MissingPublicKey, fmt.Sprintf("Failed to extract public key: %v", err), err
	}

	allowedSignersFile, err := createAllowedSignersFileWithEmail(authorEmail, publicKey)
	if err != nil {
		return VerificationError, fmt.Sprintf("Failed to create allowed signers file: %v", err), err
	}
	defer os.Remove(allowedSignersFile)

	payloadFormats := []struct { // WIP
		name string
		data []byte
	}{
		{
			name: "Original commit without signature (with final newline)",
			data: []byte(removeSSHSignatureFromCommit(content)),
		},
		{
			name: "Original commit without signature (no final newline)",
			data: []byte(strings.TrimSuffix(removeSSHSignatureFromCommit(content), "\n")),
		},
		{
			name: "Git object format with header",
			data: func() []byte {
				payload := removeSSHSignatureFromCommit(content)
				payload = strings.TrimSuffix(payload, "\n")
				return []byte(fmt.Sprintf("commit %d\x00%s", len(payload), payload))
			}(),
		},
	}

	for _, format := range payloadFormats {
		success, output, _ := verifyWithSSHKeygen(sshSig.ArmoredSignature, format.data, allowedSignersFile, authorEmail, sshSig.Namespace)
		if success {
			return ValidSignature, output, nil
		}
	}

	return InvalidSignature, "SSH signature verification failed", nil
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

func createAllowedSignersFileWithEmail(email, publicKey string) (string, error) {
	tmpFile, err := os.CreateTemp("", "allowed_signers_*.txt")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	line := fmt.Sprintf("%s namespaces=\"git\" %s\n", email, publicKey)
	if _, err := tmpFile.WriteString(line); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

func extractSSHSignatureData(content string) (*SSHSignatureData, error) {
	lines := strings.Split(content, "\n")

	sigStart := -1
	sigEnd := -1

	for i, line := range lines {
		if strings.HasPrefix(line, "gpgsig -----BEGIN SSH SIGNATURE-----") {
			sigStart = i
		}
		if strings.HasPrefix(line, " -----END SSH SIGNATURE-----") {
			sigEnd = i
			break
		}
	}

	if sigStart == -1 || sigEnd == -1 {
		return nil, fmt.Errorf("wrong SSH signature format")
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

	armoredSig := strings.Join(sigLines, "\n")

	var b64Data string
	for _, line := range sigLines {
		line = strings.TrimSpace(line)
		if line != "-----BEGIN SSH SIGNATURE-----" && line != "-----END SSH SIGNATURE-----" && line != "" {
			b64Data += line
		}
	}

	sigBlob, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}

	if len(sigBlob) < 6 || string(sigBlob[0:6]) != "SSHSIG" {
		return nil, fmt.Errorf("invalid SSH signature magic")
	}

	offset := 6

	if len(sigBlob) < offset+4 {
		return nil, fmt.Errorf("invalid signature format")
	}
	offset += 4

	if len(sigBlob) < offset+4 {
		return nil, fmt.Errorf("invalid signature format")
	}
	pubKeyLen := binary.BigEndian.Uint32(sigBlob[offset : offset+4])
	offset += 4

	if len(sigBlob) < offset+int(pubKeyLen) {
		return nil, fmt.Errorf("invalid signature format")
	}
	pubKeyBlob := sigBlob[offset : offset+int(pubKeyLen)]
	offset += int(pubKeyLen)

	if len(sigBlob) < offset+4 {
		return nil, fmt.Errorf("invalid signature format")
	}
	namespaceLen := binary.BigEndian.Uint32(sigBlob[offset : offset+4])
	offset += 4

	if len(sigBlob) < offset+int(namespaceLen) {
		return nil, fmt.Errorf("invalid signature format")
	}
	namespace := string(sigBlob[offset : offset+int(namespaceLen)])
	offset += int(namespaceLen)

	if len(sigBlob) < offset+4 {
		return nil, fmt.Errorf("invalid signature format")
	}
	reservedLen := binary.BigEndian.Uint32(sigBlob[offset : offset+4])
	offset += 4 + int(reservedLen)

	if len(sigBlob) < offset+4 {
		return nil, fmt.Errorf("invalid signature format")
	}
	hashAlgLen := binary.BigEndian.Uint32(sigBlob[offset : offset+4])
	offset += 4

	if len(sigBlob) < offset+int(hashAlgLen) {
		return nil, fmt.Errorf("invalid signature format")
	}
	hashAlg := string(sigBlob[offset : offset+int(hashAlgLen)])
	offset += int(hashAlgLen)

	if len(sigBlob) < offset+4 {
		return nil, fmt.Errorf("invalid signature format")
	}
	signatureLen := binary.BigEndian.Uint32(sigBlob[offset : offset+4])
	offset += 4

	if len(sigBlob) < offset+int(signatureLen) {
		return nil, fmt.Errorf("invalid signature format")
	}
	signature := sigBlob[offset : offset+int(signatureLen)]

	return &SSHSignatureData{
		ArmoredSignature: armoredSig,
		SignatureBlob:    sigBlob,
		Namespace:        namespace,
		HashAlgorithm:    hashAlg,
		PublicKey:        pubKeyBlob,
		Signature:        signature,
	}, nil
}

func extractPublicKeyFromSSHSignature(sigBlob []byte) (string, error) {
	if len(sigBlob) < 10 {
		return "", fmt.Errorf("signature blob too short")
	}

	offset := 6
	offset += 4

	if len(sigBlob) < offset+4 {
		return "", fmt.Errorf("invalid format")
	}
	pubKeyLen := binary.BigEndian.Uint32(sigBlob[offset : offset+4])
	offset += 4

	if len(sigBlob) < offset+int(pubKeyLen) {
		return "", fmt.Errorf("invalid format")
	}
	pubKeyBlob := sigBlob[offset : offset+int(pubKeyLen)]

	if len(pubKeyBlob) < 4 {
		return "", fmt.Errorf("public key blob too short")
	}

	keyTypeLen := binary.BigEndian.Uint32(pubKeyBlob[0:4])
	if len(pubKeyBlob) < 4+int(keyTypeLen) {
		return "", fmt.Errorf("invalid key blob")
	}

	keyType := string(pubKeyBlob[4 : 4+int(keyTypeLen)])

	keyData := base64.StdEncoding.EncodeToString(pubKeyBlob)

	return fmt.Sprintf("%s %s", keyType, keyData), nil
}

func removeSSHSignatureFromCommit(content string) string {
	lines := strings.Split(content, "\n")
	var result []string

	skipUntilEmpty := false
	for _, line := range lines {
		if strings.HasPrefix(line, "gpgsig -----BEGIN SSH SIGNATURE-----") {
			skipUntilEmpty = true
			continue
		}
		if skipUntilEmpty {
			if line == "" || !strings.HasPrefix(line, " ") {
				skipUntilEmpty = false
				if line != "" && !strings.HasPrefix(line, " ") {
					result = append(result, line)
				}
			}
			continue
		}
		result = append(result, line)
	}

	resultStr := strings.Join(result, "\n")
	if !strings.HasSuffix(resultStr, "\n") {
		resultStr += "\n"
	}

	return resultStr
}

func verifyWithSSHKeygen(armoredSig string, signedData []byte, allowedSignersFile, identity, namespace string) (bool, string, error) {
	sigFile, err := os.CreateTemp("", "*.ssh-sig")
	if err != nil {
		return false, "", err
	}
	defer os.Remove(sigFile.Name())
	defer sigFile.Close()

	dataFile, err := os.CreateTemp("", "*.txt")
	if err != nil {
		return false, "", err
	}
	defer os.Remove(dataFile.Name())
	defer dataFile.Close()

	if _, err := sigFile.Write([]byte(armoredSig)); err != nil {
		return false, "", err
	}
	sigFile.Close()

	if _, err := dataFile.Write(signedData); err != nil {
		return false, "", err
	}
	dataFile.Close()

	cmd := exec.Command("ssh-keygen", "-Y", "verify",
		"-f", allowedSignersFile,
		"-I", identity,
		"-s", sigFile.Name(),
		"-n", namespace,
		"--", dataFile.Name())

	output, err := cmd.CombinedOutput()

	if err != nil {
		return false, string(output), err
	}

	return true, string(output), nil
}

func CheckSignatureLocal(repoPath, sha string, token string, config LocalCheckConfig) ([]SignatureCheckResult, error) {
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
		catCmd := exec.Command("git", "cat-file", "commit", s)
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
