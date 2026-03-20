//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsSeparateMount(t *testing.T) {
	// /proc and /sys are virtually always separate mounts on Linux
	if !isSeparateMount("/proc") {
		t.Error("expected /proc to be a separate mount")
	}
	if !isSeparateMount("/sys") {
		t.Error("expected /sys to be a separate mount")
	}

	// Root itself should never be a separate mount from itself
	if isSeparateMount("/") {
		t.Error("/ should not be a separate mount from its parent")
	}
}

func TestResolveSymlinkForBind_NotASymlink(t *testing.T) {
	extra := resolveSymlinkForBind("/etc/hostname", false)
	if extra != nil {
		t.Errorf("expected nil for regular file, got %v", extra)
	}
}

func TestResolveSymlinkForBind_NonexistentPath(t *testing.T) {
	extra := resolveSymlinkForBind("/nonexistent/path", false)
	if extra != nil {
		t.Errorf("expected nil for nonexistent path, got %v", extra)
	}
}

func TestResolveSymlinkForBind_CrossMountSymlink(t *testing.T) {
	// /etc/mtab is commonly a symlink to /proc/self/mounts (cross-mount).
	target, err := os.Readlink("/etc/mtab")
	if err != nil {
		t.Skip("skipping: /etc/mtab is not a symlink on this system")
	}
	resolved, err := filepath.EvalSymlinks("/etc/mtab")
	if err != nil {
		t.Skip("skipping: cannot resolve /etc/mtab")
	}

	extra := resolveSymlinkForBind("/etc/mtab", false)
	if extra == nil {
		t.Skipf("skipping: /etc/mtab -> %s target is on root mount", target)
	}

	// Verify extra args contain --ro-bind for the resolved target
	foundBind := false
	for i, arg := range extra {
		if arg == "--ro-bind" && i+2 < len(extra) && extra[i+1] == resolved {
			foundBind = true
			break
		}
	}
	if !foundBind {
		t.Errorf("expected --ro-bind for target %s in extra args: %v", resolved, extra)
	}

	// Verify it starts with --tmpfs for the mount boundary
	if len(extra) < 2 || extra[0] != "--tmpfs" {
		t.Errorf("expected extra args to start with --tmpfs, got: %v", extra)
	}
}

func TestResolveSymlinkForBind_ResolvConf(t *testing.T) {
	target, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil || target == "/etc/resolv.conf" {
		t.Skip("skipping: /etc/resolv.conf is not a symlink on this system")
	}

	extra := resolveSymlinkForBind("/etc/resolv.conf", false)
	if extra == nil {
		t.Skip("skipping: resolv.conf target is reachable from root mount")
	}

	// Verify the extra args contain --ro-bind for the target
	found := false
	for i, arg := range extra {
		if arg == "--ro-bind" && i+2 < len(extra) && extra[i+1] == target {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected --ro-bind for target %s in extra args: %v", target, extra)
	}
}

// TestLinux_ResolvConfReadableInSandbox verifies that /etc/resolv.conf can be
// read inside the sandbox, even when it is a symlink to a path on a separate
// mount (e.g., /run/systemd/resolve/stub-resolv.conf on systemd-resolved systems).
func TestLinux_ResolvConfReadableInSandbox(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "cat /etc/resolv.conf", workspace)

	assertAllowed(t, result)
	if !strings.Contains(result.Stdout, "nameserver") {
		t.Errorf("expected resolv.conf to contain 'nameserver', got: %s", result.Stdout)
	}
}
