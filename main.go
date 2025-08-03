package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/output"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties"
	"github.com/ICL-ml4csec/msc-hmj24/checkthirdparties/helpers"
)

func main() {
	if len(os.Args) < 9 {
		fmt.Printf("Usage: <repository> <branch> <token> <commits|lookback> <lookback-duration-or-empty> <key-creation-cutoff> <repo-policy> <deps-policy> [output-format] [output-file]\n")
		fmt.Printf("Policy format: expired:untrusted:uncertified:missingkey:github-automated:unsigned:unauthorized (true/false for each)\n")
		fmt.Printf("Output formats: console, json, both (default: console)\n")
		fmt.Printf("Examples:\n")
		fmt.Printf("  Console only:     ... \"false:false:false:false:true:false:false\" \"true:true:true:true:true:true:true\"\n")
		fmt.Printf("  JSON file:        ... \"false:false:false:false:true:false:false\" \"true:true:true:true:true:true:true\" json report.json\n")
		fmt.Printf("  Both:             ... \"false:false:false:false:true:false:false\" \"true:true:true:true:true:true:true\" both report.json\n")
		os.Exit(1)
	}

	repo := os.Args[1]
	branch := os.Args[2]
	token := os.Args[3]

	var commitsToCheck int

	commitsArg := os.Args[4]
	lookbackArg := os.Args[5]
	keyCreationCutoffArg := os.Args[6]
	repoPolicyArg := os.Args[7]
	depsPolicyArg := os.Args[8]

	// Parse output options
	outputFormat := "console"
	outputFile := ""
	if len(os.Args) > 9 {
		outputFormat = strings.ToLower(os.Args[9])
	}
	if len(os.Args) > 10 {
		outputFile = os.Args[10]
	}

	// Validate output format
	if outputFormat != "console" && outputFormat != "json" {
		fmt.Printf("Invalid output format: %s. Must be 'console' or 'json'\n", outputFormat)
		os.Exit(1)
	}

	// Handle time-based vs commit-based checking
	if lookbackArg != "" {
		fmt.Printf("Using time-based checking (lookback: %s)\n", lookbackArg)

		if strings.ToLower(commitsArg) != "all" {
			fmt.Printf("Warning: When using lookback duration, commits parameter should be 'all'. Using 'all' instead of '%s'\n", commitsArg)
		}

		commitsToCheck = -1

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
		}
	}

	// Parse policies
	repoPolicy, err := parsePolicy(repoPolicyArg)
	if err != nil {
		log.Fatalf("Invalid repository policy: %v", err)
	}

	depsPolicy, err := parsePolicy(depsPolicyArg)
	if err != nil {
		log.Fatalf("Invalid dependencies policy: %v", err)
	}

	// Get current SHA from branch
	_, err = helpers.GetSHAFromBranch(repo, branch, token)
	if err != nil {
		fmt.Printf("Could not get latest commit SHA for branch %s: %v\n", branch, err)
		return
	}

	// Parse time cutoff
	var timeCutoff *time.Time
	if lookbackArg != "" {
		dur, _ := time.ParseDuration(lookbackArg)
		since := time.Now().Add(-dur)
		timeCutoff = &since
	}

	// Parse key creation cutoff
	var keyCreationTimeCutoff *time.Time
	if keyCreationCutoffArg != "" {
		keyCutoffDur, err := time.ParseDuration(keyCreationCutoffArg)
		if err != nil {
			log.Fatalf("invalid key creation cutoff duration: %v", err)
		}
		cutoff := time.Now().Add(-keyCutoffDur)
		keyCreationTimeCutoff = &cutoff
	}

	repoConfig := types.LocalCheckConfig{
		Branch:                  branch,
		Token:                   token,
		Repo:                    repo,
		CommitsToCheck:          -1,
		AcceptExpiredKeys:       repoPolicy.AcceptExpiredKeys,
		AcceptUnsignedCommits:   false,
		AcceptEmailMismatches:   repoPolicy.AcceptEmailMismatches,
		AcceptUncertifiedSigner: repoPolicy.AcceptUncertifiedSigner,
		AcceptMissingPublicKey:  repoPolicy.AcceptMissingPublicKey,
		AcceptGitHubAutomated:   true,
		AcceptUnregisteredKeys:  repoPolicy.AcceptUnregisteredKeys,
		TimeCutoff:              nil,
		KeyCreationCutoff:       keyCreationTimeCutoff,
	}

	depsConfig := types.LocalCheckConfig{
		Branch:                  branch,
		Token:                   token,
		Repo:                    repo,
		CommitsToCheck:          commitsToCheck,
		AcceptExpiredKeys:       depsPolicy.AcceptExpiredKeys,
		AcceptUnsignedCommits:   depsPolicy.AcceptUnsignedCommits,
		AcceptEmailMismatches:   depsPolicy.AcceptEmailMismatches,
		AcceptUncertifiedSigner: depsPolicy.AcceptUncertifiedSigner,
		AcceptMissingPublicKey:  depsPolicy.AcceptMissingPublicKey,
		AcceptGitHubAutomated:   depsPolicy.AcceptGitHubAutomated,
		AcceptUnregisteredKeys:  depsPolicy.AcceptUnregisteredKeys,
		TimeCutoff:              timeCutoff,
		KeyCreationCutoff:       keyCreationTimeCutoff,
	}

	fmt.Print("Signature verification...\n")
	// === REPOSITORY SIGNATURE CHECK ===
	results, err := checksignature.CheckSignatureLocal(repo, "", repoConfig)
	if err != nil {
		fmt.Printf("Repository signature verification failed: %v\n", err)
		return
	}

	summary := checksignature.ProcessSignatureResults(results, repoConfig)

	output.PrintRepositoryConsoleOutput(summary, repoConfig, outputFormat)

	// === DEPENDENCIES CHECK ===
	var dependencyResults []output.DependencyReport

	depResults, err := checkthirdparties.CheckThirdPartiesWithResults(token, depsConfig, timeCutoff, outputFormat)
	if err != nil {
		fmt.Printf("Dependency check failed: %v\n", err)
	} else {
		dependencyResults = depResults
	}

	if outputFormat == "json" {
		if err := output.HandleCombinedJSONOutput(summary, repoConfig, results, dependencyResults, outputFile); err != nil {
			fmt.Printf("Failed to generate combined JSON output: %v\n", err)
		}
	}

}

// parsePolicy parses a policy string in format "expired:untrusted:uncertified:missingkey:github-automated:unsigned:unauthorized"
func parsePolicy(policyStr string) (output.PolicyConfiguration, error) {
	parts := strings.Split(policyStr, ":")
	if len(parts) != 7 {
		return output.PolicyConfiguration{}, fmt.Errorf("policy must have 7 parts separated by colons, got %d parts", len(parts))
	}

	policy := output.PolicyConfiguration{}
	var err error

	policy.AcceptExpiredKeys, err = strconv.ParseBool(parts[0])
	if err != nil {
		return output.PolicyConfiguration{}, fmt.Errorf("invalid expired keys setting: %v", err)
	}

	policy.AcceptEmailMismatches, err = strconv.ParseBool(parts[1])
	if err != nil {
		return output.PolicyConfiguration{}, fmt.Errorf("invalid untrusted signers setting: %v", err)
	}

	policy.AcceptUncertifiedSigner, err = strconv.ParseBool(parts[2])
	if err != nil {
		return output.PolicyConfiguration{}, fmt.Errorf("invalid uncertified keys setting: %v", err)
	}

	policy.AcceptMissingPublicKey, err = strconv.ParseBool(parts[3])
	if err != nil {
		return output.PolicyConfiguration{}, fmt.Errorf("invalid missing public key setting: %v", err)
	}

	policy.AcceptGitHubAutomated, err = strconv.ParseBool(parts[4])
	if err != nil {
		return output.PolicyConfiguration{}, fmt.Errorf("invalid GitHub automated setting: %v", err)
	}

	policy.AcceptUnsignedCommits, err = strconv.ParseBool(parts[5])
	if err != nil {
		return output.PolicyConfiguration{}, fmt.Errorf("invalid unsigned commits setting: %v", err)
	}

	policy.AcceptUnregisteredKeys, err = strconv.ParseBool(parts[6])
	if err != nil {
		return output.PolicyConfiguration{}, fmt.Errorf("invalid unauthorized signatures setting: %v", err)
	}

	return policy, nil
}
