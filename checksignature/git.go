package checksignature

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/gpg"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/output"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/ssh"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
	"github.com/ICL-ml4csec/msc-hmj24/trustpolicies"
)

// CheckSignatureLocal performs signature verification on a Git repository
func CheckSignatureLocal(repoPath, sha string, config types.LocalCheckConfig) ([]output.SignatureCheckResult, error) {
	repoURL := fmt.Sprintf("https://github.com/%s.git", repoPath)
	tmpDir, err := os.MkdirTemp("", "repo-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	// Clone repository
	if out, err := exec.Command("git", "clone", repoURL, tmpDir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to clone: %v\n%s", err, out)
	}

	// Determine branch to use
	branchToUse := determineBranch(tmpDir, config.Branch)

	// Get list of commits to check
	commits, err := getCommitsToCheck(tmpDir, branchToUse, config)
	if err != nil {
		return nil, err
	}

	// Verify signatures for each commit
	var results []output.SignatureCheckResult
	for _, commitSHA := range commits {
		if strings.TrimSpace(commitSHA) == "" {
			continue
		}

		result := verifyCommitSignature(tmpDir, commitSHA, config)
		results = append(results, result)
	}

	return results, nil
}

// CheckAndReportSignatures performs verification and generates a report
func CheckAndReportSignatures(repoPath string, config types.LocalCheckConfig) error {
	results, err := CheckSignatureLocal(repoPath, "", config)
	if err != nil {
		return fmt.Errorf("failed to check signatures: %v", err)
	}

	summary := ProcessSignatureResults(results, config)

	// Use new console output format
	output.PrintRepositoryConsoleOutput(summary, config, repoPath)

	// Return error if any commits were rejected by policy
	if summary.RejectedByPolicy > 0 {
		return fmt.Errorf("%d commits rejected by signature policy", summary.RejectedByPolicy)
	}

	return nil
}

// determineBranch determines which branch to check
func determineBranch(tmpDir, configBranch string) string {
	branchToUse := configBranch
	checkBranchCmd := exec.Command("git", "rev-parse", "--verify", "origin/"+branchToUse)
	checkBranchCmd.Dir = tmpDir
	if err := checkBranchCmd.Run(); err != nil {
		branchToUse = helpers.GetDefaultBranch(tmpDir)
	}
	return branchToUse
}

// getCommitsToCheck builds the list of commits to verify based on configuration
func getCommitsToCheck(tmpDir, branch string, config types.LocalCheckConfig) ([]string, error) {
	var revArgs []string

	switch {
	case config.TimeCutoff != nil:
		cutoffSHA, err := trustpolicies.GetSHAFromTime(tmpDir, branch, *config.TimeCutoff)
		if err != nil {
			return nil, fmt.Errorf("failed to get SHA from time: %v", err)
		}
		if cutoffSHA != "" {
			revArgs = []string{"git", "rev-list", "origin/" + branch, "^" + cutoffSHA}
		} else {
			fmt.Printf("No commits older than %s on branch %s, checking all commits\n",
				config.TimeCutoff.Format(time.RFC3339), branch)
			revArgs = []string{"git", "rev-list", "origin/" + branch}
		}

	case config.CommitsToCheck > 0:
		revArgs = []string{"git", "rev-list", "-n", fmt.Sprint(config.CommitsToCheck), "origin/" + branch}

	default:
		revArgs = []string{"git", "rev-list", "origin/" + branch}
	}

	cmd := exec.Command(revArgs[0], revArgs[1:]...)
	cmd.Dir = tmpDir
	shaListRaw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list commits on branch %s: %v", branch, err)
	}

	shaList := strings.TrimSpace(string(shaListRaw))
	if shaList == "" {
		return []string{}, nil
	}

	return strings.Split(shaList, "\n"), nil
}

// verifyCommitSignature verifies the signature of a single commit
func verifyCommitSignature(tmpDir, commitSHA string, config types.LocalCheckConfig) output.SignatureCheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	catCmd := exec.CommandContext(ctx, "git", "cat-file", "commit", commitSHA)
	catCmd.Dir = tmpDir
	catOut, catErr := catCmd.CombinedOutput()

	if catErr != nil {
		return output.SignatureCheckResult{
			CommitSHA: commitSHA,
			Status:    string(types.VerificationError),
			Output:    string(catOut),
			Err:       catErr,
		}
	}

	author, timestamp := parseAuthorAndTimestamp(catOut)

	return determineSignatureStatus(catOut, commitSHA, config, author, timestamp)
}

func parseAuthorAndTimestamp(catOut []byte) (output.AuthorInfo, time.Time) {
	var author output.AuthorInfo
	var timestamp time.Time

	lines := strings.Split(string(catOut), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "author ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 3 {
				nameAndEmail := strings.Join(parts[1:len(parts)-2], " ")
				nameEmailSplit := strings.SplitN(nameAndEmail, "<", 2)
				if len(nameEmailSplit) == 2 {
					author.Name = strings.TrimSpace(nameEmailSplit[0])
					author.Email = strings.TrimSuffix(strings.TrimSpace(nameEmailSplit[1]), ">")
				}
				unixStr := parts[len(parts)-2]
				unixInt, err := strconv.ParseInt(unixStr, 10, 64)
				if err == nil {
					timestamp = time.Unix(unixInt, 0).UTC()
				}
			}
			break
		}
	}
	return author, timestamp
}

// determineSignatureStatus analyzes commit content and determines signature status
func determineSignatureStatus(
	catOut []byte,
	commitSHA string,
	config types.LocalCheckConfig,
	author output.AuthorInfo,
	timestamp time.Time,
) output.SignatureCheckResult {
	content := string(catOut)
	hasSSH := strings.Contains(content, "BEGIN SSH SIGNATURE")
	hasPGP := strings.Contains(content, "BEGIN PGP SIGNATURE")

	var status types.SignatureStatus
	var rawOutput string
	var err error
	var sshSig *types.SSHSignatureData

	// Verify PGP signature if present
	if hasPGP {
		status, rawOutput, err = gpg.Verify(catOut, commitSHA, config)
	}

	// Verify SSH signature if present
	if hasSSH {
		sshStatus, sshOutput, sshErr := ssh.Verify(catOut, commitSHA, config)

		// Handle dual signature scenarios
		if hasPGP {
			status, rawOutput, err = resolveDualSignatureConflict(status, rawOutput, err, sshStatus, sshOutput, sshErr)
		} else {
			status = sshStatus
			rawOutput = sshOutput
			err = sshErr
		}
	}

	// Handle unsigned commits
	if !hasPGP && !hasSSH {
		status = types.UnsignedCommit
		rawOutput = "No signature found"
	}

	author.IsAutomated = false

	if status != types.UnsignedCommit && status != types.InvalidSignature {
		author.IsAutomated = trustpolicies.IsGitHubAutomatedCommit(rawOutput, string(catOut), sshSig)
	}

	return output.SignatureCheckResult{
		CommitSHA:           commitSHA,
		Status:              string(status),
		Output:              rawOutput,
		Err:                 err,
		Author:              author,
		Timestamp:           timestamp,
		AcceptedByPolicy:    applyPolicy(string(status), config),
		HardPolicyViolation: isHardRejection(string(status), config),
	}

}

// applyPolicy checks if a signature status is acceptable based on the policy configuration
func applyPolicy(status string, config types.LocalCheckConfig) bool {
	switch status {
	case "valid":
		return true

	case "github-automated-signature":
		return config.AcceptGitHubAutomated

	case "unsigned":
		return config.AcceptUnsignedCommits

	case "signed-but-missing-key":
		return config.AcceptMissingPublicKey

	case "valid-but-expired-key":
		return config.AcceptExpiredKeys

	case "valid-but-not-certified":
		return config.AcceptUncertifiedSigner

	case "valid-but-untrusted-email":
		return config.AcceptEmailMismatches

	case "valid-but-key-not-on-github":
		return config.AcceptUnregisteredKeys

	case "invalid", "error":
		return false

	default:
		return false
	}
}

// isHardRejection checks if a commit's status is a hard rejection based on policy
func isHardRejection(status string, config types.LocalCheckConfig) bool {
	// A hard rejection occurs when a commit fails and is NOT allowed by policy
	return !applyPolicy(status, config)
}

// resolveDualSignatureConflict handles commits with both GPG and SSH signatures
func resolveDualSignatureConflict(pgpStatus types.SignatureStatus, pgpOutput string, pgpErr error,
	sshStatus types.SignatureStatus, sshOutput string, sshErr error) (types.SignatureStatus, string, error) {

	// If either signature is invalid, prefer the invalid one for security
	if pgpStatus == types.InvalidSignature {
		return pgpStatus, pgpOutput, pgpErr
	}
	if sshStatus == types.InvalidSignature {
		return sshStatus, sshOutput, sshErr
	}

	// Prefer valid SSH over non-valid PGP
	if sshStatus == types.ValidSignature && pgpStatus != types.ValidSignature {
		return sshStatus, sshOutput, sshErr
	}

	// Prefer valid PGP over non-valid SSH
	if pgpStatus == types.ValidSignature && sshStatus != types.ValidSignature {
		return pgpStatus, pgpOutput, pgpErr
	}

	// Both same status or both valid - prefer PGP (traditional Git standard)
	return pgpStatus, pgpOutput, pgpErr
}

// ProcessSignatureResults processes signature check results and applies policies
func ProcessSignatureResults(results []output.SignatureCheckResult, config types.LocalCheckConfig) output.SignatureSummary {
	summary := output.SignatureSummary{
		TotalCommits:     len(results),
		ValidSignatures:  0,
		AcceptedByPolicy: 0,
		RejectedByPolicy: 0,
		StatusBreakdown:  make(map[string]int),
		FailedCommits:    []string{},
	}

	for _, result := range results {
		status := types.SignatureStatus(result.Status)
		summary.StatusBreakdown[result.Status]++

		acceptable, reason := IsSignatureAcceptable(status, config)

		if acceptable {
			summary.AcceptedByPolicy++
			if status == types.ValidSignature {
				summary.ValidSignatures++
			}
		} else {
			summary.RejectedByPolicy++
			summary.FailedCommits = append(summary.FailedCommits,
				fmt.Sprintf("%s: %s", result.CommitSHA, reason))
		}
	}

	return summary
}
