package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ICL-ml4csec/signature-trust/client"
)

// IsValidSemver checks if a string is a valid semantic version
func IsValidSemver(version string) bool {
	var semverRegex = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[\da-zA-Z\-\.]+)?(?:\+[\da-zA-Z\-\.]+)?$`)
	return semverRegex.MatchString(version)
}

// IsPrerelease checks if a semantic version contains prerelease identifiers (has a hyphen)
func IsPrerelease(version string) bool {
	return strings.Contains(version, "-")
}

// isWildcard checks if the version string contains wildcard patterns like *.x, x, X, etc.
func isWildcard(requested string) bool {
	return strings.HasSuffix(requested, ".x") || strings.HasSuffix(requested, ".*") || requested == "x" || requested == "X" || strings.HasSuffix(requested, "x") || strings.HasSuffix(requested, "X")
}

// parseSemverParts extracts major, minor, and patch numbers from a semantic version string
func parseSemverParts(version string) [3]int {
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}
	version = strings.TrimPrefix(version, "v")

	parts := strings.Split(version, ".")
	var res [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			fmt.Printf("[WARN] Invalid semver part '%s' in version '%s', defaulting to 0\n", parts[i], version)
			return [3]int{}
		}
		res[i] = n
	}
	return res
}

// semverLess compares two semantic versions numerically and returns true if version a is less than version b
func semverLess(a, b string) bool {
	as := parseSemverParts(a)
	bs := parseSemverParts(b)
	for i := 0; i < 3; i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return false
}

// toVersionSet converts a list of versions to a set for fast lookup
func toVersionSet(list []string) map[string]struct{} {
	m := make(map[string]struct{}, len(list))
	for _, v := range list {
		m[v] = struct{}{}
	}
	return m
}

// intersect finds the common elements between two version sets (set intersection operation)
func intersect(a, b map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{})
	for k := range a {
		if _, found := b[k]; found {
			result[k] = struct{}{}
		}
	}
	return result
}

// applyComparator filters versions based on comparison operators (>=, >, <=, <, or exact match)
func applyComparator(cmp string, versions []string) []string {
	cmp = strings.TrimSpace(cmp)
	var result []string

	switch {
	case strings.HasPrefix(cmp, ">="):
		bound := strings.TrimPrefix(cmp, ">=")
		for _, v := range versions {
			if !semverLess(v, bound) {
				result = append(result, v)
			}
		}
	case strings.HasPrefix(cmp, ">"):
		bound := strings.TrimPrefix(cmp, ">")
		for _, v := range versions {
			if semverLess(bound, v) {
				result = append(result, v)
			}
		}
	case strings.HasPrefix(cmp, "<="):
		bound := strings.TrimPrefix(cmp, "<=")
		for _, v := range versions {
			if !semverLess(bound, v) {
				result = append(result, v)
			}
		}
	case strings.HasPrefix(cmp, "<"):
		bound := strings.TrimPrefix(cmp, "<")
		for _, v := range versions {
			if semverLess(v, bound) {
				result = append(result, v)
			}
		}
	default:
		for _, v := range versions {
			if v == cmp {
				result = append(result, v)
			}
		}
	}
	return result
}

// normalizeUpperLimit creates an exclusive upper bound version for range operations
func normalizeUpperLimit(v string) string {
	parts := strings.Split(v, ".")
	switch len(parts) {
	case 1:
		major, _ := strconv.Atoi(parts[0])
		return fmt.Sprintf("%d.0.0-0", major+1)
	case 2:
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		return fmt.Sprintf("%d.%d.0-0", major, minor+1)
	case 3:
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		patch, _ := strconv.Atoi(parts[2])
		return fmt.Sprintf("%d.%d.%d-0", major, minor, patch+1)
	default:
		return v + "-0"
	}
}

// Version Resolver Functions

// resolveLogicalOr handles "||" operator by trying each alternative and returning the highest version
func resolveLogicalOr(requested string, versions map[string]interface{}) string {
	parts := strings.Split(requested, "||")
	var candidates []string
	for _, part := range parts {
		resolved := ResolveVersion(strings.TrimSpace(part), versions)
		if resolved != "" {
			candidates = append(candidates, resolved)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return semverLess(candidates[i], candidates[j])
	})
	return candidates[len(candidates)-1]
}

// resolveHyphenRange handles "X.Y.Z - A.B.C" range syntax by finding the highest version within bounds
func resolveHyphenRange(requested string, versionList []string) string {
	parts := strings.Split(requested, " - ")
	if len(parts) != 2 {
		return ""
	}
	lower := strings.TrimSpace(parts[0])
	upper := normalizeUpperLimit(strings.TrimSpace(parts[1]))
	for i := len(versionList) - 1; i >= 0; i-- {
		v := versionList[i]
		if !semverLess(v, lower) && semverLess(v, upper) {
			return v
		}
	}
	return ""
}

// resolveAndComparators handles multiple space-separated conditions (e.g., ">=1.0.0 <2.0.0")
func resolveAndComparators(requested string, versionList []string) string {
	parts := strings.Fields(requested)
	if len(parts) <= 1 {
		return ""
	}
	versionSet := toVersionSet(versionList)
	for _, part := range parts {
		subset := toVersionSet(applyComparator(part, versionList))
		versionSet = intersect(versionSet, subset)
	}
	var finalList []string
	for v := range versionSet {
		finalList = append(finalList, v)
	}
	sort.Slice(finalList, func(i, j int) bool {
		return semverLess(finalList[i], finalList[j])
	})
	if len(finalList) > 0 {
		return finalList[len(finalList)-1]
	}
	return ""
}

// resolveCaret handles "^X.Y.Z" caret ranges (compatible releases)
func resolveCaret(requested string, versionList []string) string {
	baseParts := parseSemverParts(strings.TrimPrefix(requested, "^"))
	lower := fmt.Sprintf("%d.%d.%d", baseParts[0], baseParts[1], baseParts[2])
	var upper string
	if baseParts[0] > 0 {
		upper = fmt.Sprintf("%d.0.0-0", baseParts[0]+1)
	} else if baseParts[1] > 0 {
		upper = fmt.Sprintf("0.%d.0-0", baseParts[1]+1)
	} else {
		upper = fmt.Sprintf("0.0.%d-0", baseParts[2]+1)
	}
	for i := len(versionList) - 1; i >= 0; i-- {
		v := versionList[i]
		if !semverLess(v, lower) && semverLess(v, upper) {
			return v
		}
	}
	return ""
}

// resolveTilde handles "~X.Y.Z" tilde ranges (reasonably close versions)
func resolveTilde(requested string, versionList []string) string {
	clean := strings.TrimPrefix(requested, "~")
	parts := strings.Split(clean, ".")

	var lower, upper string
	switch len(parts) {
	case 1:
		major, _ := strconv.Atoi(parts[0])
		lower = fmt.Sprintf("%d.0.0", major)
		upper = fmt.Sprintf("%d.0.0-0", major+1)
	case 2:
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		lower = fmt.Sprintf("%d.%d.0", major, minor)
		upper = fmt.Sprintf("%d.%d.0-0", major, minor+1)
	default:
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		lower = fmt.Sprintf("%d.%d.%s", major, minor, parts[2])
		upper = fmt.Sprintf("%d.%d.0-0", major, minor+1)
	}

	for i := len(versionList) - 1; i >= 0; i-- {
		v := versionList[i]
		if !semverLess(v, lower) && semverLess(v, upper) {
			return v
		}
	}
	return ""
}

// resolveWildcard handles wildcard patterns like "1.x", "1.2.*", "*", "x", etc.
func resolveWildcard(requested string, versionList []string) string {
	prefix := strings.TrimSuffix(strings.TrimSuffix(requested, ".x"), ".*")
	prefix = strings.TrimSuffix(prefix, "x")
	prefix = strings.TrimSuffix(prefix, "X")
	if !strings.HasSuffix(prefix, ".") {
		prefix += "."
	}
	for i := len(versionList) - 1; i >= 0; i-- {
		if strings.HasPrefix(versionList[i], prefix) {
			return versionList[i]
		}
	}
	if requested == "x" || requested == "X" || requested == "*" {
		return versionList[len(versionList)-1]
	}
	return ""
}

// resolveExactOrComparator handles exact version matches or single comparison operators
func resolveExactOrComparator(requested string, versionList []string) string {
	filtered := applyComparator(requested, versionList)
	if len(filtered) > 0 {
		sort.Slice(filtered, func(i, j int) bool {
			return semverLess(filtered[i], filtered[j])
		})
		return filtered[len(filtered)-1]
	}
	for _, v := range versionList {
		if v == requested {
			return v
		}
	}
	return ""
}

// FindLatestSemverTag queries GitHub API to find the latest semantic version tag for a repository
func FindLatestSemverTag(repoInfo *RepoInfo, token string) (string, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/tags", repoInfo.FullName)
	resp, err := client.DoGet(url, token)
	if err != nil {
		return "", "", fmt.Errorf("error fetching tags: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub API returned HTTP %d for repo %s", resp.StatusCode, repoInfo.FullName)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("error reading tags response: %v", err)
	}

	var tags []GitHubTag
	err = json.Unmarshal(body, &tags)
	if err != nil {
		return "", "", fmt.Errorf("error parsing tags JSON: %v", err)
	}

	var semverTags []string
	tagToSHA := make(map[string]string)

	for _, tag := range tags {
		tagName := strings.TrimPrefix(tag.Name, "v")
		if IsValidSemver(tagName) {
			semverTags = append(semverTags, tag.Name)
			tagToSHA[tag.Name] = tag.Commit.SHA
		}
	}

	if len(semverTags) == 0 {
		return "", "", fmt.Errorf("no valid semver tags found for %s", repoInfo.FullName)
	}

	sort.Slice(semverTags, func(i, j int) bool {
		return semverLess(semverTags[i], semverTags[j])
	})

	latestTag := semverTags[len(semverTags)-1]
	return latestTag, tagToSHA[latestTag], nil
}

// ResolveVersion is the main entry point for semantic version resolution
// Takes a version requirement string and available versions, returns the best matching version
// Handles all semver patterns: exact, ranges, wildcards, operators, etc. Excludes prereleases
func ResolveVersion(requested string, versions map[string]interface{}) string {
	requested = strings.TrimSpace(requested)

	var versionList []string
	for v := range versions {
		if IsPrerelease(v) {
			continue
		}
		versionList = append(versionList, v)
	}
	sort.Slice(versionList, func(i, j int) bool {
		return semverLess(versionList[i], versionList[j])
	})

	var resolved string
	switch {
	case strings.Contains(requested, "||"):
		resolved = resolveLogicalOr(requested, versions)
	case strings.Contains(requested, " - "):
		resolved = resolveHyphenRange(requested, versionList)
	case strings.Contains(requested, " ") && len(strings.Fields(requested)) > 1:
		resolved = resolveAndComparators(requested, versionList)
	case strings.HasPrefix(requested, "^"):
		resolved = resolveCaret(requested, versionList)
	case strings.HasPrefix(requested, "~"):
		resolved = resolveTilde(requested, versionList)
	case isWildcard(requested):
		resolved = resolveWildcard(requested, versionList)
	default:
		resolved = resolveExactOrComparator(requested, versionList)
	}

	if IsPrerelease(resolved) {
		fmt.Printf("[INFO] Resolved version %s is a prerelease — skipping, using latest instead\n", resolved)
		return ""
	}

	if resolved == "" {
		return ""
	}

	return resolved
}
