package outputs

import (
	"fmt"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
)

func PrintSignatureResults(results []types.SignatureCheckResult, label string, config types.LocalCheckConfig) {
	fmt.Printf("Results from %s:\n", label)

	verified := 0
	for _, result := range results {
		status := result.Status
		include := false

		switch status {
		case string(types.ValidSignature):
			include = true
		case string(types.ValidSignatureButExpiredKey):
			include = config.AcceptExpiredKeys
		case string(types.ValidSignatureButSignerNotCertified):
			include = config.AcceptUncertifiedSigner
		case string(types.EmailNotMatched):
			include = config.AcceptEmailMismatches
		case string(types.MissingPublicKey):
			include = config.AcceptMissingPublicKey
		case string(types.GitHubAutomatedSignature):
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
