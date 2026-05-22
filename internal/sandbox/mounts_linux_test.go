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

// TestLinux_SessionAllowPaths verifies the two-layer Linux binding for
// --allow-path / --allow-read-path grants:
//
//   - buildDenyByDefaultMounts grants read access (--ro-bind) to every path in
//     AllowRead, i.e. both --allow-path and --allow-read-path entries.
//   - writableBindArgs adds a writable --bind only for AllowWrite entries, i.e.
//     --allow-path. Appended after the read-only binds, the later --bind wins,
//     so the path ends up writable. Read-only paths get no --bind.
//
// Covers a directory and a single file (the file exercises the !isDirectory
// branch in the read-bind layer).
func TestLinux_SessionAllowPaths(t *testing.T) {
	tmp := t.TempDir()
	rwDir := filepath.Join(tmp, "scratch")
	roDir := filepath.Join(tmp, "reference")
	roFile := filepath.Join(tmp, "reference.csv")

	if err := os.MkdirAll(rwDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(roDir, 0o750); err != nil {
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

	// Paths are normalized (symlinks resolved) before binding.
	wantRW := NormalizePath(rwDir)
	wantRODir := NormalizePath(roDir)
	wantROFile := NormalizePath(roFile)

	// Read layer: every granted path is bound read-only.
	readArgs := buildDenyByDefaultMounts(cfg, cwd, nil, nil, false)
	for _, ro := range []string{wantRW, wantRODir, wantROFile} {
		if !hasBindTriple(readArgs, "--ro-bind", ro, ro) {
			t.Errorf("granted path %q not bound readable (--ro-bind)\nargs: %v", ro, readArgs)
		}
	}

	// Write layer: only the read-write path is bound writable.
	writeArgs := writableBindArgs(cfg)
	if !hasBindTriple(writeArgs, "--bind", wantRW, wantRW) {
		t.Errorf("rw path %q not bound writable (--bind)\nargs: %v", wantRW, writeArgs)
	}
	for _, ro := range []string{wantRODir, wantROFile} {
		if hasBindTriple(writeArgs, "--bind", ro, ro) {
			t.Errorf("read-only path %q must NOT be bound writable (--bind)\nargs: %v", ro, writeArgs)
		}
	}
}
