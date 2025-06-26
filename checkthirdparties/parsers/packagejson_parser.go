package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

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
	DistTags map[string]string      `json:"dist-tags"`
}

func extractRepoURLFromNpm(npmResp NpmPackageResponse) string {
	repoURL := npmResp.Repository.URL
	if repoURL == "" {
		return ""
	}
	return repoURL
}

func printResults(depType, pkg, version, repo, sha, token string) {
	fmt.Printf("Manifest: package.json (%s)\n", depType)
	fmt.Printf("Package: %s Version: %s\n", pkg, version)
	fmt.Printf("Repository URL: %s\n", repo)
	commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=30", repo, sha)
	checksignature.CheckSignature(commitsURL, token)
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
			if helpers.IsTarballURL(version) || helpers.IsLocalPath(version) {
				fmt.Printf("[WARN] Resolution not implemented for tarballs or local paths: %q (%q)\n", pkg, version)
			}

			normalisedName, kind, cleanVersion := helpers.NormaliseDependencyName(pkg, version)
			resolved := cleanVersion

			switch kind {
			case "git":
				fmt.Printf("[INFO] Git dependency for %q: %q\n", normalisedName, cleanVersion)
				tag := helpers.ExtractGitTag(cleanVersion)
				if tag == "" {
					fmt.Printf("[WARN] No tag found in Git URL for %q\n", normalisedName)
					continue
				}
				baseURL := strings.Split(cleanVersion, "#")[0]
				repo := helpers.CleanGitHubURL(baseURL)

				sha, err := helpers.GetSHAFromTag(repo, tag, token)
				if err != nil {
					fmt.Printf("[WARN] Failed to resolve SHA for tag %q in %q: %v\n", tag, repo, err)
					continue
				}

				printResults(depType, pkg, tag, repo, sha, token)
				continue

			case "github-shorthand":
				fmt.Printf("[INFO] GitHub shorthand for %q: %q\n", normalisedName, cleanVersion)
				gitURL := helpers.ExpandGitHubShorthand(cleanVersion)
				repo := helpers.CleanGitHubURL(gitURL)
				tag := helpers.ExtractGitTag(cleanVersion)
				if tag == "" {
					tag = "latest"
				}
				sha, err := helpers.GetSHAFromTag(repo, tag, token)
				if err != nil {
					fmt.Printf("[WARN] Failed to resolve SHA for %q@%q: %v\n", repo, tag, err)
					continue
				}

				printResults(depType, normalisedName, tag, repo, sha, token)
				continue

			default:
				url := fmt.Sprintf("https://registry.npmjs.org/%s", normalisedName)
				resp, err := client.DoGet(url, token)
				if err != nil {
					fmt.Printf("[%s] Fetch failed for %s: %v\n", depType, normalisedName, err)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				defer resp.Body.Close()

				var npmResp NpmPackageResponse
				if err := json.Unmarshal(body, &npmResp); err != nil {
					fmt.Printf("[%s] Error parsing NPM JSON for %s: %v\n", depType, normalisedName, err)
					continue
				}

				if kind == "tag" {
					if tagVer, ok := npmResp.DistTags[cleanVersion]; ok {
						resolved = tagVer
					} else if latest, ok := npmResp.DistTags["latest"]; ok {
						fmt.Printf("[WARN] Tag %q missing — using latest\n", cleanVersion)
						resolved = latest
					} else {
						fmt.Printf("[ERROR] No version resolved for %q\n", normalisedName)
						continue
					}
				}

				if kind == "scoped-alias" {
					fmt.Printf("[INFO] Scoped alias %q resolved to %q @ %q\n", version, normalisedName, cleanVersion)
					resolved = cleanVersion
					pkg = normalisedName
				}

				resolved = helpers.ResolveVersion(resolved, npmResp.Versions)
				if resolved == "" {
					switch {
					case version == "":
						fmt.Printf("[WARN] No version specified for %q — using latest stable version\n", pkg)
					case version == "*" || version == "latest" || version == "X" || version == "x":
						fmt.Printf("[INFO] %q uses wildcard: %q — resolving to latest stable version\n", pkg, version)
					case helpers.IsValidSemver(version) && helpers.IsPrerelease(version):
						fmt.Printf("[INFO] Requested version %q for %q is a prerelease — using latest stable version\n", version, pkg)
					default:
						fmt.Printf("[WARN] Could not resolve version %q for %q — falling back to latest\n", version, pkg)
					}

					if latest, ok := npmResp.DistTags["latest"]; ok {
						resolved = latest
					} else {
						fmt.Printf("[ERROR] No version resolved for %q\n", pkg)
						continue
					}
				}

				repoURL := extractRepoURLFromNpm(npmResp)

				normalisedRepo := helpers.CleanGitHubURL(repoURL)
				if normalisedRepo == "" {
					fmt.Printf("[WARN] No repository URL found for %q (%q)\n", pkg, version)
					continue
				}

				sha, shaErr := helpers.GetSHAFromTag(normalisedRepo, resolved, token)
				if shaErr != nil && !strings.HasPrefix(resolved, "v") {
					sha, shaErr = helpers.GetSHAFromTag(normalisedRepo, "v"+resolved, token)
					resolved = "v" + resolved
				}
				if shaErr != nil {
					fmt.Printf("[%s] Error getting SHA for %s@%s: %v\n", depType, pkg, resolved, shaErr)
					continue
				}

				printResults(depType, pkg, resolved, normalisedRepo, sha, token)
			}
		}
	}

	processDeps("dependencies", packageJSON.Dependencies)
	processDeps("devDependencies", packageJSON.DevDependencies)

	return nil
}
