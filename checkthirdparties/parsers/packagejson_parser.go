package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/hannajonsd/git-signature-test/checksignature"
	"github.com/hannajonsd/git-signature-test/checkthirdparties/helpers"
	"github.com/hannajonsd/git-signature-test/client"
)

type PackageJSON struct {
	Dependencies map[string]string `json:"dependencies"`
}

type NpmPackageResponse struct {
	Repository struct {
		URL string `json:"url"`
	} `json:"repository"`
}

func extractRepoURLFromNpm(npmResp NpmPackageResponse) string {
	repoURL := npmResp.Repository.URL
	if repoURL == "" {
		return ""
	}
	return repoURL
}

func ParsePackageJSON(file string, token string) error {
	var packageJSON PackageJSON

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return fmt.Errorf("error parsing package.json: %v", err)
	}

	for pkg, version := range packageJSON.Dependencies {
		url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg)
		resp, err := client.DoGet(url, token)
		if err != nil {
			fmt.Printf("Error fetching NPM metadata: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response body: %v\n", err)
			continue
		}

		var npmResp NpmPackageResponse
		if err := json.Unmarshal(body, &npmResp); err != nil {
			fmt.Printf("Error parsing NPM JSON for %s: %v\n", pkg, err)
			continue
		}

		repoURL := extractRepoURLFromNpm(npmResp)

		normalizedRepo := helpers.CleanGitHubURL(repoURL)
		if normalizedRepo == "" {
			fmt.Printf("No repository URL found for %s\n", pkg)
			continue
		}

		cleanVersion := helpers.CleanVersion(version)
		versionsToTry := []string{
			cleanVersion,
			"v" + cleanVersion,
		}

		var sha string
		var shaErr error
		for _, version := range versionsToTry {
			sha, shaErr = helpers.GetSHAFromTag(normalizedRepo, version, token)
			if shaErr == nil {
				break
			}
		}

		if shaErr != nil {
			fmt.Printf("Error getting SHA for %s@%s: %v\n", pkg, cleanVersion, shaErr)
			continue
		}

		fmt.Printf("\nManifest: package.json\n")
		fmt.Printf("Package: %s Version: %s\n", pkg, cleanVersion)
		fmt.Printf("Repository URL: %s\n", normalizedRepo)

		commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=30", normalizedRepo, sha)
		checksignature.CheckSignature(commitsURL, token)
	}

	return nil
}
