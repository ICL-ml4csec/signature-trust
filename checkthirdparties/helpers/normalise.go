package helpers

import (
	"strings"
)

func IsTarballURL(version string) bool {
	return strings.HasSuffix(version, ".tgs") || strings.Contains(version, "/-/")
}

func IsLocalPath(version string) bool {
	return strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "./") || strings.HasPrefix(version, "/") || strings.HasPrefix(version, "../")
}

func NormaliseDependencyName(name, version string) (string, string, string) {
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
