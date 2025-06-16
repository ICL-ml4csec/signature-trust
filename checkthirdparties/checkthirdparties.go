package checkthirdparties

import (
	"fmt"

	"github.com/hannajonsd/git-signature-test/checkthirdparties/helpers"
	"github.com/hannajonsd/git-signature-test/checkthirdparties/parsers"
)

func CheckThirdParties(token string) {
	if helpers.FileExists("go.mod") {
		if err := parsers.ParseGo("go.mod", token); err != nil {
			fmt.Printf("%v\n", err)
		}
	}
	if helpers.FileExists("requirements.txt") {
		if err := parsers.ParseRequirements("requirements.txt", token); err != nil {
			fmt.Printf("%v\n", err)
		}
	}

	// Future manifest files here:
	// if fileExists("package.json") {...}
	// if fileExists("cargo.toml") {...}
	// if fileExists("pom.xml") {...}
}
