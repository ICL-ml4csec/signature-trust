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
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type NpmPackageResponse struct {
	Repository struct {
		URL string `json:"url"`
	} `json:"repository"`
	Versions map[string]interface{} `json:"versions"`
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
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

	processDeps := func(depType string, deps map[string]string) {
		for pkg, version := range deps {
			url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg)
			resp, err := client.DoGet(url, token)
			if err != nil {
				fmt.Printf("[%s] Error fetching NPM metadata for %s: %v\n", depType, pkg, err)
				continue
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("[%s] Error reading response body for %s: %v\n", depType, pkg, err)
				continue
			}

			var npmResp NpmPackageResponse
			if err := json.Unmarshal(body, &npmResp); err != nil {
				fmt.Printf("[%s] Error parsing NPM JSON for %s: %v\n", depType, pkg, err)
				continue
			}

			resolved := helpers.ResolveVersion(version, npmResp.Versions)
			if resolved == "" {
				switch {
				case version == "":
					fmt.Printf("[WARN] No version specified for %q — using latest stable version\n", pkg)
				case version == "*" || version == "latest" || version == "X" || version == "x":
					fmt.Printf("[INFO] %q uses wildcard: %q — resolving to latest stable version\n", pkg, "*")
				case helpers.IsValidSemver(version) && helpers.IsPrerelease(version):
					fmt.Printf("[INFO] Requested version %q for %q is a prerelease — using latest stable version\n", version, pkg)
				default:
					fmt.Printf("[WARN] Could not resolve version %q for %q — falling back to latest\n", version, pkg)
				}

				resolved = npmResp.DistTags.Latest
				if resolved == "" {
					fmt.Printf("[ERROR] No version could be resolved for %q\n", pkg)
					continue
				}
			}

			repoURL := extractRepoURLFromNpm(npmResp)

			normalizedRepo := helpers.CleanGitHubURL(repoURL)
			if normalizedRepo == "" {
				fmt.Printf("[%s] No repository URL found for %s\n", depType, pkg)
				continue
			}

			versionsToTry := []string{resolved, "v" + resolved}
			var sha string
			var shaErr error
			for _, v := range versionsToTry {
				sha, shaErr = helpers.GetSHAFromTag(normalizedRepo, v, token)
				if shaErr == nil {
					resolved = v
					break
				}
			}

			if shaErr != nil {
				fmt.Printf("[%s] Error getting SHA for %s@%s: %v\n", depType, pkg, resolved, shaErr)
				continue
			}

			fmt.Printf("Manifest: package.json (%s)\n", depType)
			fmt.Printf("Package: %s Version: %s\n", pkg, resolved)
			fmt.Printf("Repository URL: %s\n", normalizedRepo)

			commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=30", normalizedRepo, sha)
			checksignature.CheckSignature(commitsURL, token)
		}
	}

	processDeps("dependencies", packageJSON.Dependencies)
	processDeps("devDependencies", packageJSON.DevDependencies)

	return nil
}
