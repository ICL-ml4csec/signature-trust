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
		fmt.Printf("Usage: <repository> <branch> <token> <commits|all> <time-period> <key-age-period> <repo-policy> <deps-policy> [output-format] [output-file]\n")
		fmt.Printf("\n")
		fmt.Printf("Time periods: Use human-readable formats like:\n")
		fmt.Printf("  Days:    '1 day', '7 days', '30 days', '90 days'\n")
		fmt.Printf("  Weeks:   '1 week', '2 weeks', '4 weeks'\n")
		fmt.Printf("  Months:  '1 month', '3 months', '6 months'\n")
		fmt.Printf("  Years:   '1 year', '2 years', '5 years'\n")
		fmt.Printf("  Short:   '1d', '1w', '1m', '1y'\n")
		fmt.Printf("  Custom:  '10 days', '18 months', '2 years'\n")
		fmt.Printf("  Empty:   Use \"\" for no time limit\n")
		fmt.Printf("\n")
		fmt.Printf("Policy format: expired:untrusted:uncertified:missingkey:github-automated:unsigned:unauthorized (true/false for each)\n")
		fmt.Printf("Output formats: console, json (default: console)\n")
		fmt.Printf("\n")
		fmt.Printf("Examples:\n")
		fmt.Printf("  6 months back:    myrepo main token all \"6 months\" \"1 week\" \"false:false:false:false:true:false:false\" \"true:true:true:true:true:true:true\"\n")
		fmt.Printf("  1 year + JSON:    myrepo main token all \"1 year\" \"30 days\" \"false:false:false:false:true:false:false\" \"true:true:true:true:true:true:true\" json report.json\n")
		fmt.Printf("  No time limit:    myrepo main token all \"\" \"1 day\" \"false:false:false:false:true:false:false\" \"true:true:true:true:true:true:true\"\n")
		fmt.Printf("  Short format:     myrepo main token all \"3m\" \"1d\" \"false:false:false:false:true:false:false\" \"true:true:true:true:true:true:true\"\n")
		os.Exit(1)
	}

	repo := os.Args[1]
	branch := os.Args[2]
	token := os.Args[3]

	var commitsToCheck int

	commitsArg := os.Args[4]
	originalTimePeriod := os.Args[5]
	originalKeyPeriod := os.Args[6]
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
	if originalTimePeriod != "" {

		if strings.ToLower(commitsArg) != "all" {
			fmt.Printf("Warning: When using time-range duration, commits parameter should be 'all'. Using 'all' instead of '%s'\n", commitsArg)
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
		os.Exit(1)
	}

	// Parse time cutoff
	var timeCutoff *time.Time
	var keyCreationTimeCutoff *time.Time

	// Parse time cutoff
	timeCutoff, err = helpers.ParseTimePeriod(originalTimePeriod)
	if err != nil {
		fmt.Printf("Invalid time cutoff period: %v\n", err)
		fmt.Printf("Supported formats: %v\n", helpers.GetSupportedTimePeriods())
		return
	}

	// Parse key creation cutoff
	keyCreationTimeCutoff, err = helpers.ParseTimePeriod(originalKeyPeriod)
	if err != nil {
		fmt.Printf("Invalid key age cutoff period: %v\n", err)
		fmt.Printf("Supported formats: %v\n", helpers.GetSupportedTimePeriods())
		return
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
		OriginalTimePeriod:      originalTimePeriod,
		OriginalKeyPeriod:       originalKeyPeriod,
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
		OriginalTimePeriod:      originalTimePeriod,
		OriginalKeyPeriod:       originalKeyPeriod,
	}

	fmt.Print("Signature verification...\n")
	// === REPOSITORY SIGNATURE CHECK ===
	results, err := checksignature.CheckSignatureLocal(repo, "", repoConfig)
	if err != nil {
		fmt.Printf("Repository signature verification failed: %v\n", err)
		os.Exit(1)
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

	repoFailed := summary.RejectedByPolicy > 0

	depsFailed := false
	for _, dep := range dependencyResults {
		if dep.Status == "FAILED" {
			depsFailed = true
			break
		}
	}

	if repoFailed || depsFailed {
		fmt.Printf("\n❌ Signature verification failed\n")
		if repoFailed {
			fmt.Printf("  - Repository: %d commits rejected by policy\n", summary.RejectedByPolicy)
		}
		if depsFailed {
			fmt.Printf("  - Dependencies: Some dependencies failed policy checks\n")
		}
		os.Exit(1)
	} else {
		fmt.Printf("\n✅ All signature checks passed\n")
		os.Exit(0)
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
