package archive

import "testing"

func TestNormalizeLogTypesUsesConfiguredTypesByDefault(t *testing.T) {
	got := normalizeLogTypes("", []string{"nginx-access", "php-error", "nginx-access", "  ", "mysql"})
	want := []string{"nginx-access", "php-error", "mysql"}
	if len(got) != len(want) {
		t.Fatalf("normalizeLogTypes length = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizeLogTypes[%d] = %q, want %q; got %#v", i, got[i], want[i], got)
		}
	}
}

func TestNormalizeLogTypesKeepsExplicitLogType(t *testing.T) {
	got := normalizeLogTypes(" php-error ", []string{"nginx-access", "mysql"})
	if len(got) != 1 || got[0] != "php-error" {
		t.Fatalf("normalizeLogTypes explicit = %#v, want php-error", got)
	}
}

func TestNormalizeLogTypesFallsBackToAccess(t *testing.T) {
	got := normalizeLogTypes("", nil)
	if len(got) != 1 || got[0] != "nginx-access" {
		t.Fatalf("normalizeLogTypes fallback = %#v, want nginx-access", got)
	}
}
