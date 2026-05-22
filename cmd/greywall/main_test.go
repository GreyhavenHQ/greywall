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
