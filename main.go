package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
	"github.com/ICL-ml4csec/msc-hmj24/outputs"
)

func main() {
	if len(os.Args) < 12 {
		fmt.Printf("Usage: <repository> <branch> <token> <commits|lookback> <expired> <untrusted> <uncertified> <missingkey> <github-automated> <lookback-duration-or-empty> <key-creation-cutoff>\n")
		fmt.Printf("Examples:\n")
		fmt.Printf("  Check last 10 commits: ... 10 ... \"\"\n")
		fmt.Printf("  Check last 6 months:   ... all ... \"4320h\"\n")
		os.Exit(1)
	}

	repo := os.Args[1]
	branch := os.Args[2]
	token := os.Args[3]

	var commitsToCheck int
	var oldestSHA string

	commitsArg := os.Args[4]
	lookbackArg := os.Args[10]

	if lookbackArg != "" {
		fmt.Printf("Using time-based checking (lookback: %s)\n", lookbackArg)

		if strings.ToLower(commitsArg) != "all" {
			fmt.Printf("Warning: When using lookback duration, commits parameter should be 'all'. Using 'all' instead of '%s'\n", commitsArg)
		}

		commitsToCheck = -1

		dur, err := time.ParseDuration(lookbackArg)
		if err != nil {
			log.Fatalf("invalid lookback duration (%q): %v", lookbackArg, err)
		}
		since := time.Now().Add(-dur)
		fmt.Printf("Time-based cutoff: %s (checking commits newer than this)\n", since.Format(time.RFC3339))

		oldestSHA = ""

		if oldestSHA != "" {
			fmt.Printf("Found cutoff SHA: %s\n", oldestSHA)
		} else {
			fmt.Printf("No cutoff SHA found - will check all commits\n")
		}
	} else {
		if strings.ToLower(commitsArg) == "all" {
			fmt.Printf("Using commit-based checking (all commits)\n")
			commitsToCheck = -1
		} else {
			var err error
			commitsToCheck, err = strconv.Atoi(commitsArg)
			if err != nil {
				fmt.Printf("Invalid number for commits-to-check: %v\n. Use a number or 'all'.", commitsArg)
				os.Exit(1)
			}
			fmt.Printf("Using commit-based checking (last %d commits)\n", commitsToCheck)
		}
		oldestSHA = ""
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
	var timeCutoff *time.Time
	if lookbackArg != "" {
		dur, _ := time.ParseDuration(lookbackArg)
		since := time.Now().Add(-dur)
		timeCutoff = &since
	}

	var keyCreationTimeCutoff *time.Time
	if len(os.Args) > 11 && os.Args[11] != "" {
		keyCutoffDur, err := time.ParseDuration(os.Args[11])
		if err != nil {
			log.Fatalf("invalid key creation cutoff duration: %v", err)
		}
		cutoff := time.Now().Add(-keyCutoffDur)
		keyCreationTimeCutoff = &cutoff
	}

	// fmt.Printf("Checking commits for repository: %s on branch: %s\n", repo, branch)
	// checksignature.CheckSignature(repo, branch, token, commitsToCheck)

	fmt.Printf("Checking commits locally for repository: %s on branch: %s\n", repo, branch)
	config := checksignature.LocalCheckConfig{
		Branch:                 branch,
		Token:                  token,
		CommitsToCheck:         commitsToCheck,
		OldestSHA:              oldestSHA,
		AcceptExpiredKeys:      acceptExpiredKeys,
		AcceptUntrustedSigners: acceptUntrustedSigners,
		AcceptUncertifiedKeys:  acceptUncertifiedKeys,
		AcceptMissingPublicKey: acceptMissingPublicKey,
		AcceptGitHubAutomated:  acceptGitHubAutomated,
		TimeCutoff:             timeCutoff,
		KeyCreationCutoff:      keyCreationTimeCutoff,
	}

	results, err := checksignature.CheckSignatureLocal(repo, sha, config)
	if err != nil {
		fmt.Println("Error checking signatures locally:", err)
		return
	}
	outputs.PrintSignatureResults(results, "Local", config)

	fmt.Printf("Checking third-party libraries in manifest files...\n")
	checkthirdparties.CheckThirdParties(token, config, timeCutoff)
}
