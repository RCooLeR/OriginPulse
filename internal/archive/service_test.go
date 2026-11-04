package archive

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"originpulse/internal/config"
)

func TestRemoveArchivedSourcesMarksMissingRootSourcesDeleted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing-combined")
	cfg := config.Default()
	cfg.Combiner.CombinedDir = root
	s := NewService(cfg, nil)
	store := &sourceDeletionRecorder{}
	deleted, failed, err := s.removeArchivedSources(context.Background(), store, group{
		Segments: []segment{{ID: "segment-id", Path: filepath.Join(root, "source.log")}},
	})
	if err != nil || deleted != 0 || failed != 0 {
		t.Fatalf("cleanup = %d, %d, %v; want 0, 0, nil", deleted, failed, err)
	}
	if len(store.ids) != 1 || store.ids[0] != "segment-id" {
		t.Fatalf("sources marked deleted = %v, want segment-id", store.ids)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("missing combined root was created: %v", err)
	}
}

type sourceDeletionRecorder struct {
	ids []string
}

func (r *sourceDeletionRecorder) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "source_deleted_at = now()") {
		r.ids = append(r.ids, args[0].(string))
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

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
