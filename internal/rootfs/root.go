package rootfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrOutsideRoot = errors.New("path is outside configured root")

type Root struct {
	base string
	dir  *os.Root
}

func Open(path string) (*Root, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("root path is required")
	}
	base, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve root path: %w", err)
	}
	dir, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open root %q: %w", base, err)
	}
	return &Root{base: filepath.Clean(base), dir: dir}, nil
}

func (r *Root) Close() error {
	if r == nil || r.dir == nil {
		return nil
	}
	return r.dir.Close()
}

func (r *Root) Remove(path string) (bool, error) {
	relative, err := r.relative(path)
	if err != nil {
		return false, err
	}
	if err := r.dir.Remove(relative); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *Root) PruneEmptyParents(path string, max int) {
	if max <= 0 {
		return
	}
	relative, err := r.relative(path)
	if err != nil {
		return
	}
	parent := filepath.Dir(relative)
	for range max {
		if parent == "." || parent == "" || parent == string(filepath.Separator) {
			return
		}
		if err := r.dir.Remove(parent); err != nil {
			return
		}
		parent = filepath.Dir(parent)
	}
}

func (r *Root) relative(path string) (string, error) {
	if r == nil || r.dir == nil {
		return "", errors.New("root is closed")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	relative, err := filepath.Rel(r.base, absolute)
	if err != nil {
		return "", fmt.Errorf("make path relative to root: %w", err)
	}
	if relative == "." || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("%w: %q", ErrOutsideRoot, path)
	}
	return relative, nil
}
