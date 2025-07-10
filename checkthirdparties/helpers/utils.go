package helpers

import (
	"fmt"
	"os"

	"github.com/ICL-ml4sec/msc-hmj24/checksignature"
)

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func PrintSignatureResults(results []checksignature.SignatureCheckResult, label string) {
	fmt.Printf("Results from %s:\n", label)

	verified := 0
	for _, result := range results {
		if result.Status == string(checksignature.ValidSignature) ||
			result.Status == string(checksignature.ExpiredButValidSignature) { // Make configurable (include/exclude)
			verified++
		} else if result.Status == string(checksignature.ValidSignatureButNotCertified) {
			fmt.Printf("Flagged commit %s as valid but not certified.\n", result.CommitSHA)
			verified++
		} else {
			fmt.Printf("Commit %s status: %s\n\n", result.CommitSHA, result.Status)
			continue
		}
		fmt.Printf("Commit %s status: %s\n\nOutput:\n%s\n", result.CommitSHA, result.Status, result.Output)
	}

	percent := float64(verified) / float64(len(results)) * 100
	fmt.Printf("%s verified commits: %.2f%%\n\n", label, percent)
}
