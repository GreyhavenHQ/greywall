package sandbox

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGetDefaultWritePaths(t *testing.T) {
	paths := GetDefaultWritePaths()

	if len(paths) == 0 {
		t.Error("GetDefaultWritePaths() returned empty slice")
	}

	essentialPaths := []string{"/dev/stdout", "/dev/stderr", "/dev/null"}
	for _, essential := range essentialPaths {
		found := slices.Contains(paths, essential)
		if !found {
			t.Errorf("GetDefaultWritePaths() missing essential path %q", essential)
		}
	}
}

func TestGetMandatoryDenyPatterns(t *testing.T) {
	cwd := "/home/user/project"

	tests := []struct {
		name             string
		cwd              string
		allowGitConfig   bool
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:           "with git config denied",
			cwd:            cwd,
			allowGitConfig: false,
			shouldContain: []string{
				filepath.Join(cwd, ".gitconfig"),
				filepath.Join(cwd, ".bashrc"),
				filepath.Join(cwd, ".zshrc"),
				filepath.Join(cwd, ".git/hooks"),
				filepath.Join(cwd, ".git/config"),
				"**/.gitconfig",
				"**/.bashrc",
				"**/.git/hooks/**",
				"**/.git/config",
			},
		},
		{
			name:           "with git config allowed",
			cwd:            cwd,
			allowGitConfig: true,
			shouldContain: []string{
				filepath.Join(cwd, ".gitconfig"),
				filepath.Join(cwd, ".git/hooks"),
				"**/.git/hooks/**",
			},
			shouldNotContain: []string{
				filepath.Join(cwd, ".git/config"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := GetMandatoryDenyPatterns(tt.cwd, tt.allowGitConfig)

			for _, expected := range tt.shouldContain {
				found := slices.Contains(patterns, expected)
				if !found {
					t.Errorf("GetMandatoryDenyPatterns() missing pattern %q", expected)
				}
			}

			for _, notExpected := range tt.shouldNotContain {
				found := slices.Contains(patterns, notExpected)
				if found {
					t.Errorf("GetMandatoryDenyPatterns() should not contain %q when allowGitConfig=%v", notExpected, tt.allowGitConfig)
				}
			}
		})
	}
}

func TestGetMandatoryDenyPatternsContainsDangerousFiles(t *testing.T) {
	cwd := "/test/project"
	patterns := GetMandatoryDenyPatterns(cwd, false)

	// Each dangerous file should appear both as a cwd-relative path and as a glob pattern
	for _, file := range DangerousFiles {
		cwdPath := filepath.Join(cwd, file)
		globPattern := "**/" + file

		foundCwd := false
		foundGlob := false

		for _, p := range patterns {
			if p == cwdPath {
				foundCwd = true
			}
			if p == globPattern {
				foundGlob = true
			}
		}

		if !foundCwd {
			t.Errorf("Missing cwd-relative pattern for dangerous file %q", file)
		}
		if !foundGlob {
			t.Errorf("Missing glob pattern for dangerous file %q", file)
		}
	}
}

func TestGetMandatoryDenyPatternsContainsDangerousDirectories(t *testing.T) {
	cwd := "/test/project"
	patterns := GetMandatoryDenyPatterns(cwd, false)

	for _, dir := range DangerousDirectories {
		cwdPath := filepath.Join(cwd, dir)
		globPattern := "**/" + dir + "/**"

		foundCwd := false
		foundGlob := false

		for _, p := range patterns {
			if p == cwdPath {
				foundCwd = true
			}
			if p == globPattern {
				foundGlob = true
			}
		}

		if !foundCwd {
			t.Errorf("Missing cwd-relative pattern for dangerous directory %q", dir)
		}
		if !foundGlob {
			t.Errorf("Missing glob pattern for dangerous directory %q", dir)
		}
	}
}

func TestGetMandatoryDenyPatternsGitHooksAlwaysBlocked(t *testing.T) {
	cwd := "/test/project"

	// Git hooks should be blocked regardless of allowGitConfig
	for _, allowGitConfig := range []bool{true, false} {
		patterns := GetMandatoryDenyPatterns(cwd, allowGitConfig)

		foundHooksPath := false
		foundHooksGlob := false

		for _, p := range patterns {
			if p == filepath.Join(cwd, ".git/hooks") {
				foundHooksPath = true
			}
			if strings.Contains(p, ".git/hooks") && strings.HasPrefix(p, "**") {
				foundHooksGlob = true
			}
		}

		if !foundHooksPath || !foundHooksGlob {
			t.Errorf("Git hooks should always be blocked (allowGitConfig=%v)", allowGitConfig)
		}
	}
}
