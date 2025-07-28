package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ICL-ml4sec/msc-hmj24/checksignature"
	"github.com/ICL-ml4sec/msc-hmj24/checkthirdparties"
	"github.com/ICL-ml4sec/msc-hmj24/checkthirdparties/helpers"
)

func main() {
	if len(os.Args) < 9 {
		fmt.Printf("Expected 8 arguments: <repository> <branch> <token> <commits> <expired> <untrusted> <uncertified> <missingkey>\n")
		os.Exit(1)
	}

	repo := os.Args[1]
	branch := os.Args[2]
	token := os.Args[3]

	var commitsToCheck int
	arg := os.Args[4]
	if strings.ToLower(arg) == "all" {
		commitsToCheck = -1
	} else {
		var err error
		commitsToCheck, err = strconv.Atoi(arg)
		if err != nil {
			fmt.Printf("Invalid number for commits-to-check: %v\n. Use a number or 'all'.", os.Args[4])
			os.Exit(1)
		}
	}

	acceptExpiredKeys := strings.ToLower(os.Args[5]) == "true"
	acceptUntrustedSigners := strings.ToLower(os.Args[6]) == "true"
	acceptUncertifiedKeys := strings.ToLower(os.Args[7]) == "true"
	acceptMissingPublicKey := strings.ToLower(os.Args[8]) == "true"
	acceptGitHubAutomated := strings.ToLower(os.Args[9]) == "true"

	sha, err := helpers.GetSHAFromBranch(repo, branch, token)
	if err != nil {
		fmt.Printf("Could not get latest commit SHA for branch %s: %v\n", branch, err)
		return
	}

	fmt.Printf("Checking commits for repository: %s on branch: %s\n", repo, branch)
	checksignature.CheckSignature(repo, sha, token, commitsToCheck)

	fmt.Printf("Checking commits locally for repository: %s on branch: %s\n", repo, branch)

	config := checksignature.LocalCheckConfig{
		CommitsToCheck:         commitsToCheck,
		AcceptExpiredKeys:      acceptExpiredKeys,
		AcceptUntrustedSigners: acceptUntrustedSigners,
		AcceptUncertifiedKeys:  acceptUncertifiedKeys,
		AcceptMissingPublicKey: acceptMissingPublicKey,
		AcceptGitHubAutomated:  acceptGitHubAutomated,
	}

	results, err := checksignature.CheckSignatureLocal(repo, sha, config)
	if err != nil {
		fmt.Println("Error checking signatures locally:", err)
		return
	}
	helpers.PrintSignatureResults(results, "Local", config)

	fmt.Printf("Checking third-party libraries in manifest files...\n")
	checkthirdparties.CheckThirdParties(token, config)
}
