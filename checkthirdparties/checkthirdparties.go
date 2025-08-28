package checkthirdparties

import (
	"fmt"
	"os"
	"time"

	"github.com/ICL-ml4csec/signature-trust/checksignature/output"
	"github.com/ICL-ml4csec/signature-trust/checksignature/types"
	goparser "github.com/ICL-ml4csec/signature-trust/checkthirdparties/parsers/go"
	jsparser "github.com/ICL-ml4csec/signature-trust/checkthirdparties/parsers/javascript"
	pyparser "github.com/ICL-ml4csec/signature-trust/checkthirdparties/parsers/python"
)

// fileExists checks if a file exists at the given path
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

// CheckThirdPartiesWithResults checks third-party dependencies and returns detailed results
func CheckThirdPartiesWithResults(token string, config types.LocalCheckConfig, timeCutoff *time.Time, outputFormat string) ([]output.DependencyReport, error) {
	var results []output.DependencyReport

	if fileExists("go.mod") {
		depResults, err := goparser.ParseGo("go.mod", token, config, timeCutoff, outputFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			return nil, err
		}
		results = append(results, depResults...)

	}

	if fileExists("package.json") {
		depResults, err := jsparser.ParsePackageJSON("package.json", token, config, timeCutoff, outputFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			return nil, err
		}
		results = append(results, depResults...)

	}

	if fileExists("requirements.txt") {
		depResults, err := pyparser.ParseRequirements("requirements.txt", token, config, timeCutoff, outputFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			return nil, err
		}
		results = append(results, depResults...)

	}

	return results, nil
}
