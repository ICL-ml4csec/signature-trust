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
			result.Status == string(checksignature.ExpiredButValidSignature) ||
			result.Status == string(checksignature.ValidSignatureButNotCertified) {
			verified++
		} else {
			fmt.Printf("Commit %s status: %s\nOutput:\n%s\n\n", result.CommitSHA, result.Status, result.Output)
			continue
		}
		fmt.Printf("Verified commit %s status: %s\n\n", result.CommitSHA, result.Status)
	}

	percent := float64(verified) / float64(len(results)) * 100
	fmt.Printf("%s verified commits: %.2f%%\n\n", label, percent)
}
