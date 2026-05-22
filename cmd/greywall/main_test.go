// Package main implements the greywall CLI.
package main

import (
	"slices"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// TestApplySessionAllowPaths verifies that --allow-path grants read+write while
// --allow-read-path grants read-only, both appended to the session config.
func TestApplySessionAllowPaths(t *testing.T) {
	tests := []struct {
		name      string
		rwPaths   []string
		roPaths   []string
		baseRead  []string
		baseWrite []string
		wantRead  []string
		wantWrite []string
	}{
		{
			name:      "no flags leaves config untouched",
			wantRead:  nil,
			wantWrite: nil,
		},
		{
			name:      "allow-path adds to both read and write",
			rwPaths:   []string{"/tmp/work"},
			wantRead:  []string{"/tmp/work"},
			wantWrite: []string{"/tmp/work"},
		},
		{
			name:      "allow-read-path adds to read only",
			roPaths:   []string{"/data/refs"},
			wantRead:  []string{"/data/refs"},
			wantWrite: nil,
		},
		{
			name:      "both flags combine: rw in both, ro in read only",
			rwPaths:   []string{"/tmp/out"},
			roPaths:   []string{"/data/refs", "/data/reference.csv"},
			wantRead:  []string{"/data/refs", "/data/reference.csv", "/tmp/out"},
			wantWrite: []string{"/tmp/out"},
		},
		{
			name:      "appends to existing config paths",
			rwPaths:   []string{"/tmp/work"},
			baseRead:  []string{"/existing/read"},
			baseWrite: []string{"/existing/write"},
			wantRead:  []string{"/existing/read", "/tmp/work"},
			wantWrite: []string{"/existing/write", "/tmp/work"},
		},
		{
			name:      "multiple rw paths repeatable",
			rwPaths:   []string{"/tmp/a", "/tmp/b"},
			wantRead:  []string{"/tmp/a", "/tmp/b"},
			wantWrite: []string{"/tmp/a", "/tmp/b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  tt.baseRead,
					AllowWrite: tt.baseWrite,
				},
			}

			applySessionAllowPaths(cfg, tt.rwPaths, tt.roPaths)

			if !slices.Equal(cfg.Filesystem.AllowRead, tt.wantRead) {
				t.Errorf("AllowRead = %v, want %v", cfg.Filesystem.AllowRead, tt.wantRead)
			}
			if !slices.Equal(cfg.Filesystem.AllowWrite, tt.wantWrite) {
				t.Errorf("AllowWrite = %v, want %v", cfg.Filesystem.AllowWrite, tt.wantWrite)
			}
		})
	}
}

// TestProxyIdentity is the regression test for #96. The greyproxy session
// container name and the SOCKS5 login are both derived from proxyIdentity, so
// they can never diverge. Before the fix, the container name was derived
// independently as `cmdName || "sandbox"` and ignored --proxy-user, so a run
// with --proxy-user registered its --allow / profile rules under a container
// name that no live connection ever logged in as, and the rules were silently
// dropped. The "flag overrides command name" case below pins the behavior the
// old container-name derivation got wrong (it would have returned "curl").
func TestProxyIdentity(t *testing.T) {
	tests := []struct {
		name          string
		proxyUserFlag string
		cmdName       string
		want          string
	}{
		{"flag overrides command name", "agent1", "curl", "agent1"},
		{"flag overrides empty command", "agent1", "", "agent1"},
		{"command name when no flag", "", "curl", "curl"},
		{"fallback when both empty", "", "", "proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxyIdentity(tt.proxyUserFlag, tt.cmdName); got != tt.want {
				t.Errorf("proxyIdentity(%q, %q) = %q, want %q",
					tt.proxyUserFlag, tt.cmdName, got, tt.want)
			}
		})
	}
}
