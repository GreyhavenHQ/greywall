//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// hasBindTriple reports whether args contains the consecutive sequence
// [flag, src, dst] (bubblewrap emits bind mounts as three separate args).
// Note "--bind" does not match "--ro-bind" since the tokens differ exactly.
func hasBindTriple(args []string, flag, src, dst string) bool {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == flag && args[i+1] == src && args[i+2] == dst {
			return true
		}
	}
	return false
}

// TestLinux_SessionAllowPaths verifies that buildDenyByDefaultMounts binds
// --allow-path entries writable (--bind) and --allow-read-path entries
// read-only (--ro-bind, never --bind). Covers a directory and a single file
// (the file exercises the !isDirectory branch).
func TestLinux_SessionAllowPaths(t *testing.T) {
	tmp := t.TempDir()
	rwDir := filepath.Join(tmp, "scratch")
	roDir := filepath.Join(tmp, "reference")
	roFile := filepath.Join(tmp, "reference.csv")

	if err := os.MkdirAll(rwDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(roDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roFile, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	cwd := t.TempDir()

	cfg := config.Default()
	// --allow-path appends to both AllowRead and AllowWrite; --allow-read-path
	// to AllowRead only. Mirror that wiring here.
	cfg.Filesystem.AllowRead = []string{roDir, roFile, rwDir}
	cfg.Filesystem.AllowWrite = []string{rwDir}

	args := buildDenyByDefaultMounts(cfg, cwd, nil, nil, false)

	// Paths are normalized (symlinks resolved) before binding.
	wantRW := NormalizePath(rwDir)
	wantRODir := NormalizePath(roDir)
	wantROFile := NormalizePath(roFile)

	// Read-write dir must be bound writable.
	if !hasBindTriple(args, "--bind", wantRW, wantRW) {
		t.Errorf("rw path %q not bound writable (--bind)\nargs: %v", wantRW, args)
	}

	// Read-only dir and file: bound read-only, never writable.
	for _, ro := range []string{wantRODir, wantROFile} {
		if !hasBindTriple(args, "--ro-bind", ro, ro) {
			t.Errorf("read-only path %q not bound --ro-bind\nargs: %v", ro, args)
		}
		if hasBindTriple(args, "--bind", ro, ro) {
			t.Errorf("read-only path %q must NOT be bound writable (--bind)\nargs: %v", ro, args)
		}
	}
}
