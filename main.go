package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ICL-ml4sec/msc-hmj24/checksignature"
	"github.com/ICL-ml4sec/msc-hmj24/checkthirdparties"
	"github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/helpers"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Expected 3 arguments: <repository> <branch> <token>\n")
		os.Exit(1)
	}

	repo := os.Args[1]
	branch := os.Args[2]
	token := os.Args[3]
	commitsToCheck, err := strconv.Atoi(os.Args[4])
	if err != nil {
		fmt.Printf("Invalid number for commits-to-check: %v\n", os.Args[4])
		os.Exit(1)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=%v", repo, branch, commitsToCheck)
	fmt.Printf("Checking commits for repository: %s on branch: %s\n", repo, branch)

	checksignature.CheckSignature(url, token)

	fmt.Printf("Checking commits locally for repository: %s on branch: %s\n", repo, branch)
	sha, err := helpers.GetSHAFromBranch(repo, branch, token)
	if err != nil {
		fmt.Printf("Could not get latest commit SHA for branch %s: %v\n", branch, err)
		return
	}

	config := checksignature.LocalCheckConfig{
		MaxCommits: commitsToCheck,
	}

	results, err := checksignature.CheckSignatureLocal(repo, sha, token, config)
	if err != nil {
		fmt.Println("Error checking signatures locally:", err)
		return
	}
	helpers.PrintSignatureResults(results, "Local")

	fmt.Printf("Checking third-party libraries in manifest files...\n")
	checkthirdparties.CheckThirdParties(token, commitsToCheck)
}
