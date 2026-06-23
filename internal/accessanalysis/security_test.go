package accessanalysis

import (
	"regexp"
	"strings"
	"testing"
)

func TestPathTraversalRegexDoesNotMatchEllipsisURL(t *testing.T) {
	re := regexp.MustCompile(pathTraversalRegex)
	target := strings.ToLower("/products/example-service?lid=dProducts-and-Services/.../Category/Other-Category.aspx")

	if re.MatchString(target) {
		t.Fatalf("pathTraversalRegex matched ordinary ellipsis URL: %q", target)
	}
}

func TestPathTraversalRegexMatchesDirectoryTraversal(t *testing.T) {
	re := regexp.MustCompile(pathTraversalRegex)
	tests := []string{
		"/force-download.php?file=../wp-config.php",
		"/cgi-bin/%2e%2e/%2e%2e/bin/sh",
		"/download?file=..%2f..%2fetc/passwd",
	}

	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			if !re.MatchString(strings.ToLower(target)) {
				t.Fatalf("pathTraversalRegex did not match traversal target: %q", target)
			}
		})
	}
}

func TestInjectionProbeLabelsAreCalmer(t *testing.T) {
	if got := injectionProbeTitle("path_traversal"); got != "Directory traversal attempt" {
		t.Fatalf("path traversal title = %q", got)
	}
	if got := injectionProbeTitle("secret_file"); got != "Sensitive file request" {
		t.Fatalf("sensitive file title = %q", got)
	}
}

func TestSQLSelectRegexDoesNotMatchEnglishURL(t *testing.T) {
	re := regexp.MustCompile(sqlSelectFromRegex)
	target := strings.ToLower("/news/example-customer-selects-example-platform/")

	if re.MatchString(target) {
		t.Fatalf("sqlSelectFromRegex matched ordinary content URL: %q", target)
	}
}

func TestSQLSelectRegexMatchesEncodedSelectFrom(t *testing.T) {
	re := regexp.MustCompile(sqlSelectFromRegex)
	target := strings.ToLower("/module/example?id=1;select%20name%20from%20users")

	if !re.MatchString(target) {
		t.Fatalf("sqlSelectFromRegex did not match encoded select/from payload: %q", target)
	}
}
