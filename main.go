package main

import (
	"fmt"
	"os"

	"github.com/hannajonsd/git-signature-test/checksignature"
	"github.com/hannajonsd/git-signature-test/checkthirdparties"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Expected 3 arguments: <repository> <branch> <token>\n")
		os.Exit(1)
	}

	repo := os.Args[1]
	branch := os.Args[2]
	token := os.Args[3]

	url := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=100", repo, branch)
	fmt.Printf("Checking commits for repository: %s on branch: %s\n", repo, branch)

	checksignature.CheckSignature(url, token)

	fmt.Printf("Checking third-party libraries in manifest files...\n")
	checkthirdparties.CheckThirdParties(token)
}
