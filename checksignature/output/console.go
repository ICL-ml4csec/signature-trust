package output

import (
	"fmt"
	"strings"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
)

// PrintRepositoryConsoleOutput displays a detailed report of signature verification results
// for all commits in a repository.
func PrintRepositoryConsoleOutput(summary SignatureSummary, config types.LocalCheckConfig, outputFormat string) {
	fmt.Printf("\n=== REPOSITORY SIGNATURE CHECK ===\n")
	fmt.Printf("Checking all commits for branch: %s\n", config.Branch)

	// Show key age policy if configured
	if config.KeyCreationCutoff != nil {
		fmt.Printf("Key age policy: Signing keys must be older than %s (%s)\n",
			config.OriginalKeyPeriod,
			config.KeyCreationCutoff.Format("2 Jan 2006"))
	}

	fmt.Printf("\n== RESULTS ==\n")
	fmt.Printf("Signature Check Summary (%s):\n", config.Repo)
	fmt.Printf("    Total commits: %d\n", summary.TotalCommits)
	fmt.Printf("    Valid signatures: %d\n", summary.ValidSignatures)

	// Policy result
	if summary.RejectedByPolicy == 0 {
		fmt.Printf("    Policy Result: PASSED\n")
	} else {
		fmt.Printf("    Policy Result: FAILED\n")
	}
	fmt.Printf("       * Accepted: %d\n", summary.AcceptedByPolicy)
	fmt.Printf("       * Rejected: %d\n", summary.RejectedByPolicy)
	fmt.Printf("    Security Score: %.1f%%\n", CalculateSecurityScore(summary))

	// Policy-dependent rejections
	policyRejections := getPolicyDependentRejections(summary, config)
	if len(policyRejections) > 0 {
		fmt.Printf("\nPolicy-dependent rejections:\n")
		for category, commits := range policyRejections {
			fmt.Printf("    - %s: %d commits\n", category, len(commits))

			// Show commits with details
			maxShow := 3
			if outputFormat == "console" {
				maxShow = len(commits) // Show all for console
			}

			for i, commit := range commits {
				if i < maxShow {
					fmt.Printf("      * %s: %s\n", commit.SHA, commit.Description)
				}
			}

			if len(commits) > maxShow {
				fmt.Printf("      * ... and %d more (see JSON report for full details)\n", len(commits)-maxShow)
			}
		}

	}

	// Hard rejections
	hardRejections := getHardRejections(summary)
	if len(hardRejections) > 0 {
		fmt.Printf("\nHard rejections:\n")
		for category, commits := range hardRejections {
			fmt.Printf("    - %s: %d commits\n", category, len(commits))
			// Show commits with details
			maxShow := 3
			if outputFormat == "console" {
				maxShow = len(commits) // Show all for console
			}

			for i, commit := range commits {
				if i < maxShow {
					fmt.Printf("      * %s: %s\n", commit.SHA, commit.Description)
				}
			}

			if len(commits) > maxShow {
				fmt.Printf("      * ... and %d more (see JSON report for full details)\n", len(commits)-maxShow)
			}
		}
	}
	fmt.Println()

}

// PrintDependencyConsoleOutput displays signature check results for a third-party dependency.
func PrintDependencyConsoleOutput(summary SignatureSummary, config types.LocalCheckConfig, manifest, packageName, version string, commitsChecked int, outputFormat string) {
	fmt.Printf("=== THIRD-PARTY DEPENDENCIES CHECK ===\n")

	if config.CommitsToCheck == -1 {
		fmt.Printf("Checking all commits in third-party library:\n")
	} else {
		fmt.Printf("Checking %d commits in third-party library:\n", commitsChecked)
	}

	fmt.Printf("     Manifest: %s\n", manifest)
	fmt.Printf("     Package: %s Version: %s\n", packageName, version)

	if config.TimeCutoff != nil {
		fmt.Printf("     Commits newer than %s (%s)\n",
			config.OriginalTimePeriod,
			config.TimeCutoff.Format("2 Jan 2006"))
	}

	if config.KeyCreationCutoff != nil {
		fmt.Printf("     Key age policy: Signing keys must be older than %s (%s)\n",
			config.OriginalKeyPeriod,
			config.KeyCreationCutoff.Format("2 Jan 2006"))
	}

	fmt.Printf("\n== RESULTS ==\n")
	if commitsChecked == 0 {
		return
	}

	fmt.Printf("Signature Check Summary (%s):\n", packageName)
	fmt.Printf("    Total commits: %d\n", summary.TotalCommits)
	fmt.Printf("    Valid signatures: %d\n", summary.ValidSignatures)

	if summary.RejectedByPolicy == 0 {
		fmt.Printf("    Policy Result: PASSED\n")
	} else {
		fmt.Printf("    Policy Result: FAILED\n")
	}
	fmt.Printf("       * Accepted: %d\n", summary.AcceptedByPolicy)
	fmt.Printf("       * Rejected: %d\n", summary.RejectedByPolicy)
	fmt.Printf("    Security Score: %.1f%%\n", CalculateSecurityScore(summary))

	// Policy-dependent rejections
	policyRejections := getPolicyDependentRejections(summary, config)
	if len(policyRejections) > 0 {
		fmt.Printf("\nPolicy-dependent rejections:\n")
		for category, commits := range policyRejections {
			fmt.Printf("    - %s: %d commits\n", category, len(commits))

			// Show commits with details
			maxShow := 3
			if outputFormat == "console" {
				maxShow = len(commits) // Show all for console
			}

			for i, commit := range commits {
				if i < maxShow {
					fmt.Printf("      * %s: %s\n", commit.SHA, commit.Description)
				}
			}

			if len(commits) > maxShow {
				fmt.Printf("      * ... and %d more (see JSON report for full details)\n", len(commits)-maxShow)
			}

		}
	}

	// Hard rejections
	hardRejections := getHardRejections(summary)
	if len(hardRejections) > 0 {
		fmt.Printf("\nHard rejections:\n")
		for category, commits := range hardRejections {
			fmt.Printf("    - %s: %d commits\n", category, len(commits))

			// Show commits with details
			maxShow := 3
			if outputFormat == "console" {
				maxShow = len(commits) // Show all for console
			}

			for i, commit := range commits {
				if i < maxShow {
					fmt.Printf("      * %s: %s\n", commit.SHA, commit.Description)
				}
			}

			if len(commits) > maxShow {
				fmt.Printf("      * ... and %d more (see JSON report for full details)\n", len(commits)-maxShow)
			}
		}
	}
}

// getPolicyDependentRejections returns commits rejected due to configurable trust policies.
// These rejections depend on user-defined settings in the verification config.
func getPolicyDependentRejections(summary SignatureSummary, config types.LocalCheckConfig) map[string][]CommitFailure {
	rejections := make(map[string][]CommitFailure)

	// Parse the failed commits and categorize them based on policy
	for _, failure := range summary.FailedCommits {
		parts := strings.SplitN(failure, ":", 2)
		if len(parts) != 2 {
			continue
		}

		sha := parts[0]
		description := strings.TrimSpace(parts[1])
		commit := CommitFailure{SHA: sha, Description: description}

		switch {
		case strings.Contains(description, "Missing public key") && !config.AcceptMissingPublicKey:
			rejections["Missing keys on GitHub"] = append(rejections["Missing keys on GitHub"], commit)
		case strings.Contains(description, "not found") && !config.AcceptMissingPublicKey:
			rejections["Missing keys on GitHub"] = append(rejections["Missing keys on GitHub"], commit)
		case strings.Contains(description, "mismatch") && !config.AcceptEmailMismatches:
			rejections["Email mismatches"] = append(rejections["Email mismatches"], commit)
		case strings.Contains(description, "created") && strings.Contains(description, "ago"):
			rejections["Recent keys (newer than policy)"] = append(rejections["Recent keys (newer than policy)"], commit)
		case strings.Contains(description, "expired") && !config.AcceptExpiredKeys:
			rejections["Expired keys"] = append(rejections["Expired keys"], commit)
		case strings.Contains(description, "not certified") && !config.AcceptUncertifiedSigner:
			rejections["Uncertified signers"] = append(rejections["Uncertified signers"], commit)
		case strings.Contains(description, "unauthorized") && !config.AcceptUnregisteredKeys:
			rejections["Unregistered signers"] = append(rejections["Unregistered signers"], commit)
		case strings.Contains(description, "Unsigned commit") && !config.AcceptUnsignedCommits:
			rejections["Unsigned commits"] = append(rejections["Unsigned commits"], commit)
		case strings.Contains(description, "No signature") && !config.AcceptUnsignedCommits:
			rejections["Unsigned commits"] = append(rejections["Unsigned commits"], commit)
		}
	}

	return rejections
}

// getHardRejections returns commits that failed verification due to invalid, corrupted,
// or cryptographically broken signatures — these are always rejected regardless of policy.
func getHardRejections(summary SignatureSummary) map[string][]CommitFailure {
	rejections := make(map[string][]CommitFailure)

	for _, failure := range summary.FailedCommits {
		parts := strings.SplitN(failure, ":", 2)
		if len(parts) != 2 {
			continue
		}

		sha := parts[0]
		description := strings.TrimSpace(parts[1])
		commit := CommitFailure{SHA: sha, Description: description}

		// Only truly broken signatures go here - things that are NEVER acceptable
		switch {
		case strings.Contains(description, "broken") || strings.Contains(description, "failed"):
			rejections["Invalid signatures"] = append(rejections["Invalid signatures"], commit)
		case strings.Contains(description, "cryptographically broken"):
			rejections["Invalid signatures"] = append(rejections["Invalid signatures"], commit)
		case strings.Contains(description, "verification failed"):
			rejections["Invalid signatures"] = append(rejections["Invalid signatures"], commit)
		}
	}

	return rejections
}

// CalculateSecurityScore computes the security score based on accepted commits
func CalculateSecurityScore(summary SignatureSummary) float64 {
	if summary.TotalCommits == 0 {
		return 0.0
	}
	return float64(summary.AcceptedByPolicy) / float64(summary.TotalCommits) * 100
}
