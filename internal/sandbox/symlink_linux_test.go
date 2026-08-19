//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLinux_SymlinkedShellConfigReadable verifies that symlinked dotfiles
// (e.g., ~/.zshrc managed by GNU Stow) are readable inside the sandbox in
// deny-by-default mode. Previously, canMountOver() rejected symlinks entirely,
// causing bwrap to skip them.
func TestLinux_SymlinkedShellConfigReadable(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")

	workspace := createTempWorkspace(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	// Create a symlinked shell config using one of the recognized names.
	// Use .inputrc since it's unlikely to exist on CI runners.
	configName := ".inputrc"
	symlinkPath := filepath.Join(home, configName)

	// Skip if .inputrc already exists (don't overwrite real config)
	if fileExists(symlinkPath) {
		t.Skipf("skipping: %s already exists", symlinkPath)
	}

	// Create the real file inside the workspace
	realFile := filepath.Join(workspace, "dotfiles", configName)
	if err := os.MkdirAll(filepath.Dir(realFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realFile, []byte("# greywall symlink test\nset editing-mode vi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("failed to create test symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(symlinkPath) })

	// Use deny-by-default mode (where buildDenyByDefaultMounts is used)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = boolPtr(true)

	result := runUnderSandbox(t, cfg, "cat "+symlinkPath, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "greywall symlink test")
}

// TestLinux_SymlinkedAllowReadPath verifies that user-specified allowRead paths
// that are symlinks are resolved and accessible inside the sandbox.
func TestLinux_SymlinkedAllowReadPath(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")

	workspace := createTempWorkspace(t)

	// Create a real file and a symlink to it
	realFile := filepath.Join(workspace, "real-data.txt")
	if err := os.WriteFile(realFile, []byte("symlink-test-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(workspace, "link-data.txt")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatal(err)
	}

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = boolPtr(true)
	cfg.Filesystem.AllowRead = []string{symlink}

	result := runUnderSandbox(t, cfg, "cat "+symlink, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "symlink-test-content")
}

// TestLinux_SymlinkedAllowReadPathLegacyMode verifies that symlinked allowRead
// paths work in legacy mode (--ro-bind / /) too.
func TestLinux_SymlinkedAllowReadPathLegacyMode(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")

	workspace := createTempWorkspace(t)

	realFile := filepath.Join(workspace, "real-data.txt")
	if err := os.WriteFile(realFile, []byte("legacy-symlink-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(workspace, "link-data.txt")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatal(err)
	}

	cfg := testConfigWithWorkspace(workspace)
	// Legacy mode: defaultDenyRead=false (default from testConfig)

	// In legacy mode, symlinks within the workspace should just work since
	// --ro-bind / / carries the whole root filesystem (non-recursive bind
	// still includes same-mount content).
	result := runUnderSandbox(t, cfg, "cat "+symlink, workspace)

	assertAllowed(t, result)
	if !strings.Contains(result.Stdout, "legacy-symlink-test") {
		t.Errorf("expected to read symlinked file content, got: %s", result.Stdout)
	}
}
