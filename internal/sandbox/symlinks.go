package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinkScanEntries caps how many directory entries a deep symlink scan
// visits, so a huge allowed directory cannot stall sandbox startup.
const maxSymlinkScanEntries = 10000

// SymlinkEntry describes a symbolic link in an allowed path whose target the
// sandbox must also expose for the link to resolve.
type SymlinkEntry struct {
	Link     string // absolute path of the symlink itself
	LinkDest string // raw link content from os.Readlink (may be relative)
	Target   string // fully resolved absolute target
}

// resolveSymlinkEntry returns the SymlinkEntry for p when p is a symlink with
// a resolvable target. Returns ok=false for regular paths, dangling links,
// and unreadable links.
func resolveSymlinkEntry(p string) (SymlinkEntry, bool) {
	info, err := os.Lstat(p) // Lstat doesn't follow symlinks
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return SymlinkEntry{}, false
	}
	linkDest, err := os.Readlink(p)
	if err != nil {
		return SymlinkEntry{}, false
	}
	target, err := filepath.EvalSymlinks(p)
	if err != nil {
		return SymlinkEntry{}, false
	}
	return SymlinkEntry{Link: p, LinkDest: linkDest, Target: target}, true
}

// sensitiveScanTargets lists paths the escaping-symlink scan must never
// auto-expose. Allowed directories can be writable inside the sandbox, so a
// sandboxed process could plant a symlink there and have the next session
// bind its target. Explicit allowRead grants are unaffected.
func sensitiveScanTargets() []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		for _, d := range SensitiveUserDirs {
			paths = append(paths, filepath.Join(home, d))
		}
	}
	return append(paths, GetSensitiveSystemPaths()...)
}

// isSensitiveScanTarget returns true when target must not be auto-exposed by
// the escaping-symlink scan.
func isSensitiveScanTarget(target string) bool {
	for _, p := range sensitiveScanTargets() {
		if target == p || strings.HasPrefix(target, p+string(filepath.Separator)) {
			return true
		}
	}
	// Credential-bearing project files (.env and variants).
	base := filepath.Base(target)
	for _, f := range SensitiveProjectFiles {
		if base == f {
			return true
		}
	}
	return strings.HasPrefix(base, ".env.")
}

// scanEscapingSymlinks finds symlinks under root whose resolved target lies
// outside root. Those targets are not reachable inside the sandbox unless
// they are exposed separately. With deep=false only root's direct entries are
// examined (a single directory read). With deep=true the whole tree is
// walked, bounded by maxSymlinkScanEntries.
func scanEscapingSymlinks(root string, deep, debug bool) []SymlinkEntry {
	root = filepath.Clean(root)
	prefix := root + string(filepath.Separator)
	var entries []SymlinkEntry

	collect := func(p string) {
		entry, ok := resolveSymlinkEntry(p)
		if !ok {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:symlink] Skipping unresolvable symlink: %s\n", p)
			}
			return
		}
		if entry.Target == root || strings.HasPrefix(entry.Target, prefix) {
			return // target stays inside the allowed directory
		}
		if isSensitiveScanTarget(entry.Target) {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:symlink] Not exposing sensitive symlink target: %s -> %s\n", p, entry.Target)
			}
			return
		}
		entries = append(entries, entry)
	}

	if !deep {
		dirEntries, err := os.ReadDir(root)
		if err != nil {
			return nil
		}
		for _, e := range dirEntries {
			if e.Type()&fs.ModeSymlink != 0 {
				collect(filepath.Join(root, e.Name()))
			}
		}
		return entries
	}

	visited := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best-effort scan: skip unreadable entries
		}
		visited++
		if visited > maxSymlinkScanEntries {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:symlink] Deep scan of %s stopped after %d entries\n", root, maxSymlinkScanEntries)
			}
			return filepath.SkipAll
		}
		if d.Type()&fs.ModeSymlink != 0 {
			collect(p)
		}
		return nil
	})
	return entries
}
