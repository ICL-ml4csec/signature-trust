package checkthirdparties

import (
	"fmt"
	"os"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature"
	goparser "github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/parsers/go"
	// jsparser "github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/parsers/javascript"
	// pyparser "github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/parsers/python"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func CheckThirdParties(token string, config checksignature.LocalCheckConfig, timeCutoff *time.Time) {
	if fileExists("go.mod") {
		if err := goparser.ParseGo("go.mod", token, config, timeCutoff); err != nil {
			fmt.Printf("%v\n", err)
		}
	}

	// if helpers.FileExists("requirements.txt") {
	// 	if err := pyparser.ParseRequirements("requirements.txt", token, config.CommitsToCheck); err != nil {
	// 		fmt.Printf("%v\n", err)
	// 	}
	// }
	// if helpers.FileExists("package.json") {
	// 	if err := jsparser.ParsePackageJSON("package.json", token, config.CommitsToCheck, config); err != nil {
	// 		fmt.Printf("%v\n", err)
	// 	}
	// }

	// Future manifest files here:
	// if fileExists("package.json") {...}
	// if fileExists("cargo.toml") {...}
	// if fileExists("pom.xml") {...}
}
