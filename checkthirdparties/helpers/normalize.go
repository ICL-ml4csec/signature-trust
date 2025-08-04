package helpers

import (
	"strings"
)

// IsTarballURL checks if the version string indicates a tarball URL
func IsTarballURL(version string) bool {
	return strings.HasSuffix(version, ".tgs") || strings.HasSuffix(version, ".tar.gz") || strings.HasSuffix(version, ".tgz")
}

// IsLocalPath checks if the version string indicates a local file path
func IsLocalPath(version string) bool {
	return strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "./") || strings.HasPrefix(version, "/") || strings.HasPrefix(version, "../")
}

// NormalizeDependencyName normalises the dependency name and version
func NormalizeDependencyName(name, version string) (string, string, string) {
	switch {
	case strings.HasPrefix(version, "git+"):
		return name, "git", version
	case strings.Contains(version, "/") && !strings.Contains(version, "@") && !strings.HasPrefix(version, "npm:"):
		return name, "github-shorthand", version
	case strings.HasPrefix(version, "npm:"):
		trimmed := strings.TrimPrefix(version, "npm:")
		atIdx := strings.LastIndex(trimmed, "@")
		if atIdx > 0 {
			realName := trimmed[:atIdx]
			realVersion := trimmed[atIdx+1:]
			return realName, "scoped-alias", realVersion
		}
		return trimmed, "scoped-alias", "latest"
	case version == "latest" || version == "beta":
		return name, "tag", version
	default:
		return name, "registry", version
	}
}
