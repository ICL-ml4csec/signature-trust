package outputs

import (
	"fmt"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature"
)

func PrintSignatureResults(results []checksignature.SignatureCheckResult, label string, config checksignature.LocalCheckConfig) {
	fmt.Printf("Results from %s:\n", label)

	verified := 0
	for _, result := range results {
		status := result.Status
		include := false

		switch status {
		case string(checksignature.ValidSignature):
			include = true
		case string(checksignature.ExpiredButValidSignature):
			include = config.AcceptExpiredKeys
		case string(checksignature.ValidSignatureButNotCertified):
			include = config.AcceptUncertifiedKeys
		case string(checksignature.EmailNotMatched):
			include = config.AcceptUntrustedSigners
		case string(checksignature.MissingPublicKey):
			include = config.AcceptMissingPublicKey
		case string(checksignature.GitHubAutomatedSignature):
			include = config.AcceptGitHubAutomated
		}

		if include {
			verified++
			fmt.Printf("Verified commit %s status: %s\n\n", result.CommitSHA, result.Status)
		} else {
			fmt.Printf("Commit %s status: %s\nOutput:\n%s\n\n", result.CommitSHA, result.Status, result.Output)
		}
	}

	if verified == 0 {
		fmt.Printf("No verified commits found in %s results.\n\n", label)
		return
	}

	percent := float64(verified) / float64(len(results)) * 100
	fmt.Printf("%s verified commits: %.2f%%\n\n", label, percent)
}
