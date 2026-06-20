package retention

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveLocalFilesDeletesFilesAndPrunesEmptyParents(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "raw", "site", "live")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(nested, "nginx-access.log")
	if err := os.WriteFile(path, []byte("line\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	deleted, failed := removeLocalFiles([]string{path})
	if deleted != 1 || failed != 0 {
		t.Fatalf("removeLocalFiles() = deleted %d failed %d, want 1/0", deleted, failed)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("removed file still exists or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "raw")); !os.IsNotExist(err) {
		t.Fatalf("empty parent directories should be pruned, stat error: %v", err)
	}
}

func TestRemoveLocalFilesIgnoresMissingFiles(t *testing.T) {
	deleted, failed := removeLocalFiles([]string{filepath.Join(t.TempDir(), "missing.log")})
	if deleted != 0 || failed != 0 {
		t.Fatalf("removeLocalFiles() = deleted %d failed %d, want 0/0", deleted, failed)
	}
}

func TestRemoveLocalFilesReportsDeletionFailures(t *testing.T) {
	root := t.TempDir()
	nonEmptyDir := filepath.Join(root, "archive")
	if err := os.MkdirAll(nonEmptyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "child"), []byte("keep"), 0o644); err != nil {
		t.Fatalf("write child: %v", err)
	}

	deleted, failed := removeLocalFiles([]string{nonEmptyDir})
	if deleted != 0 || failed != 1 {
		t.Fatalf("removeLocalFiles() = deleted %d failed %d, want 0/1", deleted, failed)
	}
}
