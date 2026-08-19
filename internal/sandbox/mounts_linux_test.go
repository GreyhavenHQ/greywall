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

// TestLinux_SymlinkedAllowRead covers issue #91: allowRead entries that are
// symlinks must work inside the sandbox. The link is recreated (--symlink)
// and its resolved target is bound at the target's real path, so opening the
// link path and the realpath both work.
func TestLinux_SymlinkedAllowRead(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "real.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Filesystem.AllowRead = []string{link}

	args := buildDenyByDefaultMounts(cfg, t.TempDir(), nil, nil, false)
	if !hasBindTriple(args, "--symlink", target, link) {
		t.Errorf("symlink %s not recreated (--symlink %s %s)\nargs: %v", link, target, link, args)
	}
	if !hasBindTriple(args, "--ro-bind", target, target) {
		t.Errorf("symlink target %s not bound readable\nargs: %v", target, args)
	}
}

// TestLinux_EscapingSymlinkInAllowedDir verifies that symlinks inside an
// allowed directory pointing outside it get their targets bound, per the
// filesystem.symlinkScan mode.
func TestLinux_EscapingSymlinkInAllowedDir(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(tmp, "outside.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tmp, "allowed")
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "top-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sub, "deep-link")); err != nil {
		t.Fatal(err)
	}

	cwd := t.TempDir()
	cfg := config.Default()
	cfg.Filesystem.AllowRead = []string{dir}

	// Default (shallow): direct entries scanned, target bound.
	args := buildDenyByDefaultMounts(cfg, cwd, nil, nil, false)
	if !hasBindTriple(args, "--ro-bind", outside, outside) {
		t.Errorf("shallow scan: escaping symlink target %s not bound\nargs: %v", outside, args)
	}

	// Off: no scan, target not bound.
	cfg.Filesystem.SymlinkScan = config.SymlinkScanOff
	args = buildDenyByDefaultMounts(cfg, cwd, nil, nil, false)
	if hasBindTriple(args, "--ro-bind", outside, outside) {
		t.Errorf("scan off: escaping symlink target %s must not be bound\nargs: %v", outside, args)
	}

	// Deep: nested links found too. Remove the top-level link so only the
	// nested one can produce the bind.
	if err := os.Remove(filepath.Join(dir, "top-link")); err != nil {
		t.Fatal(err)
	}
	cfg.Filesystem.SymlinkScan = config.SymlinkScanShallow
	args = buildDenyByDefaultMounts(cfg, cwd, nil, nil, false)
	if hasBindTriple(args, "--ro-bind", outside, outside) {
		t.Errorf("shallow scan: nested symlink target %s must not be bound\nargs: %v", outside, args)
	}
	cfg.Filesystem.SymlinkScan = config.SymlinkScanDeep
	args = buildDenyByDefaultMounts(cfg, cwd, nil, nil, false)
	if !hasBindTriple(args, "--ro-bind", outside, outside) {
		t.Errorf("deep scan: nested symlink target %s not bound\nargs: %v", outside, args)
	}
}

// TestLinux_SymlinkedAllowWrite verifies writableBindArgs recreates symlinked
// allowWrite entries and binds their targets writable.
func TestLinux_SymlinkedAllowWrite(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "data")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "data-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Filesystem.AllowWrite = []string{link}

	args := writableBindArgs(cfg)
	if !hasBindTriple(args, "--symlink", target, link) {
		t.Errorf("symlink %s not recreated\nargs: %v", link, args)
	}
	if !hasBindTriple(args, "--bind", target, target) {
		t.Errorf("symlink target %s not bound writable\nargs: %v", target, args)
	}
}
