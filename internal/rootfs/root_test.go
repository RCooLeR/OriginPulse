package rootfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveStaysWithinRoot(t *testing.T) {
	workspace := t.TempDir()
	base := filepath.Join(workspace, "root")
	inside := filepath.Join(base, "nested", "deeper", "inside.log")
	outside := filepath.Join(workspace, "outside.log")
	if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	removed, err := root.Remove(inside)
	if err != nil || !removed {
		t.Fatalf("remove inside = %v, %v; want true, nil", removed, err)
	}
	root.PruneEmptyParents(inside, 6)
	if _, err := os.Stat(filepath.Join(base, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nested directory still exists or stat failed unexpectedly: %v", err)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("configured root was removed: %v", err)
	}

	removed, err = root.Remove(outside)
	if removed || !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("remove outside = %v, %v; want false, ErrOutsideRoot", removed, err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside file was changed: %v", err)
	}
}

func TestRemoveRejectsSymlinkEscape(t *testing.T) {
	workspace := t.TempDir()
	base := filepath.Join(workspace, "root")
	outsideDir := filepath.Join(workspace, "outside")
	outside := filepath.Join(outsideDir, "outside.log")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(base, "escape")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	root, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if removed, err := root.Remove(filepath.Join(base, "escape", "outside.log")); err == nil || removed {
		t.Fatalf("symlink escape removal = %v, %v; want false and an error", removed, err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside file was changed: %v", err)
	}
}
