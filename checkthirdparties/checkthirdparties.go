package checkthirdparties

import (
	"fmt"
	"os"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/output"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	goparser "github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/parsers/go"
	// jsparser "github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/parsers/javascript"
	// pyparser "github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/parsers/python"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func CheckThirdPartiesWithResults(token string, config types.LocalCheckConfig, timeCutoff *time.Time) ([]output.DependencyReport, error) {
	var results []output.DependencyReport

	if fileExists("go.mod") {
		depResults, err := goparser.ParseGoWithResults("go.mod", token, config, timeCutoff)
		if err != nil {
			fmt.Printf("%v\n", err)
			return nil, err
		}
		results = append(results, depResults...)

	}

	return results, nil
}
