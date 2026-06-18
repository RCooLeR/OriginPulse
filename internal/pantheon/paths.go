package pantheon

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var unsafePathChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func NormalizeRemotePath(remotePath string) string {
	cleaned := path.Clean(strings.ReplaceAll(remotePath, `\`, `/`))
	cleaned = strings.TrimPrefix(cleaned, "/")
	return cleaned
}

func LocalRawPath(rawDir string, siteID string, env string, containerID string, remotePath string) string {
	relative := NormalizeRemotePath(remotePath)
	relative = strings.TrimPrefix(relative, "logs/")
	if relative == "logs" || relative == "." {
		relative = ""
	}
	parts := []string{rawDir, siteID, env, containerID}
	if relative != "" {
		for _, part := range strings.Split(relative, "/") {
			parts = append(parts, sanitizePathPart(part))
		}
	}
	return filepath.Join(parts...)
}

func ContainerID(kind string, address string) string {
	value := unsafePathChars.ReplaceAllString(address, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		value = "unknown"
	}
	return kind + "-" + value
}

func DetectLogType(remotePath string) string {
	base := strings.ToLower(path.Base(NormalizeRemotePath(remotePath)))
	base = strings.TrimSuffix(base, ".gz")

	switch {
	case strings.HasPrefix(base, "nginx-access.log"):
		return "nginx-access"
	case strings.HasPrefix(base, "nginx-error.log"):
		return "nginx-error"
	case strings.HasPrefix(base, "php-error.log"):
		return "php-error"
	case strings.HasPrefix(base, "php-slow.log"):
		return "php-slow"
	case strings.Contains(base, "slow") && strings.Contains(base, "mysql"):
		return "mysql-slow"
	case strings.Contains(base, "mysql"):
		return "mysql"
	default:
		return "unknown"
	}
}

func sanitizePathPart(value string) string {
	value = unsafePathChars.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" || value == "." || value == ".." {
		return "unknown"
	}
	return value
}
