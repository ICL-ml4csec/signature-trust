package checkthirdparties

import (
	"fmt"

	"github.com/ICL-ml4sec/msc-hmj24/checksignature"
	"github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/helpers"
	goparser "github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/parsers/go"
	jsparser "github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/parsers/javascript"
	pyparser "github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/parsers/python"
)

func CheckThirdParties(token string, config checksignature.LocalCheckConfig) {
	if helpers.FileExists("go.mod") {
		if err := goparser.ParseGo("go.mod", token, config); err != nil {
			fmt.Printf("%v\n", err)
		}
	}

	if helpers.FileExists("requirements.txt") {
		if err := pyparser.ParseRequirements("requirements.txt", token, config.CommitsToCheck); err != nil {
			fmt.Printf("%v\n", err)
		}
	}
	if helpers.FileExists("package.json") {
		if err := jsparser.ParsePackageJSON("package.json", token, config.CommitsToCheck); err != nil {
			fmt.Printf("%v\n", err)
		}
	}

	// Future manifest files here:
	// if fileExists("package.json") {...}
	// if fileExists("cargo.toml") {...}
	// if fileExists("pom.xml") {...}
}
