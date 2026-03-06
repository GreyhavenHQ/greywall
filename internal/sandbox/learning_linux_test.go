//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractWritePath(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "openat with O_WRONLY",
			line:     `12345 openat(AT_FDCWD, "/home/user/.cache/opencode/db", O_WRONLY|O_CREAT, 0644) = 3`,
			expected: "/home/user/.cache/opencode/db",
		},
		{
			name:     "openat with O_RDWR",
			line:     `12345 openat(AT_FDCWD, "/home/user/.cache/opencode/data", O_RDWR|O_CREAT, 0644) = 3`,
			expected: "/home/user/.cache/opencode/data",
		},
		{
			name:     "openat with O_CREAT",
			line:     `12345 openat(AT_FDCWD, "/home/user/file.txt", O_CREAT|O_WRONLY, 0644) = 3`,
			expected: "/home/user/file.txt",
		},
		{
			name:     "openat read-only ignored",
			line:     `12345 openat(AT_FDCWD, "/home/user/readme.txt", O_RDONLY) = 3`,
			expected: "",
		},
		{
			name:     "mkdirat",
			line:     `12345 mkdirat(AT_FDCWD, "/home/user/.cache/opencode", 0755) = 0`,
			expected: "/home/user/.cache/opencode",
		},
		{
			name:     "unlinkat",
			line:     `12345 unlinkat(AT_FDCWD, "/home/user/temp.txt", 0) = 0`,
			expected: "/home/user/temp.txt",
		},
		{
			name:     "creat",
			line:     `12345 creat("/home/user/newfile", 0644) = 3`,
			expected: "/home/user/newfile",
		},
		{
			name:     "failed syscall ignored",
			line:     `12345 openat(AT_FDCWD, "/nonexistent", O_WRONLY|O_CREAT, 0644) = -1 ENOENT (No such file or directory)`,
			expected: "",
		},
		{
			name:     "unfinished syscall ignored",
			line:     `12345 openat(AT_FDCWD, "/home/user/file", O_WRONLY <unfinished ...>`,
			expected: "",
		},
		{
			name:     "non-write syscall ignored",
			line:     `12345 read(3, "data", 1024) = 5`,
			expected: "",
		},
		{
			name:     "renameat2 returns destination",
			line:     `12345 renameat2(AT_FDCWD, "/home/user/old.txt", AT_FDCWD, "/home/user/new.txt", 0) = 0`,
			expected: "/home/user/new.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractWritePath(tt.line)
			if got != tt.expected {
				t.Errorf("extractWritePath(%q) = %q, want %q", tt.line, got, tt.expected)
			}
		})
	}
}

func TestShouldFilterPath(t *testing.T) {
	home := "/home/testuser"
	tests := []struct {
		path     string
		expected bool
	}{
		{"/proc/self/maps", true},
		{"/sys/kernel/mm/transparent_hugepage", true},
		{"/dev/null", true},
		{"/tmp/somefile", true},
		{"/run/user/1000/bus", true},
		{"/home/testuser/.cache/opencode/db", false},
		{"/usr/lib/libfoo.so", true},           // .so file
		{"/usr/lib/libfoo.so.1", true},         // .so.X file
		{"/tmp/greywall-strace-abc.log", true}, // greywall infrastructure
		{"relative/path", true},                // relative path
		{"", true},                             // empty path
		{"/other/user/file", true},             // outside home
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := shouldFilterPath(tt.path, home)
			if got != tt.expected {
				t.Errorf("shouldFilterPath(%q, %q) = %v, want %v", tt.path, home, got, tt.expected)
			}
		})
	}
}

func TestParseStraceLog(t *testing.T) {
	home, _ := os.UserHomeDir()

	logContent := strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + filepath.Join(home, ".cache/testapp/db") + `", O_WRONLY|O_CREAT, 0644) = 3`,
		`12345 openat(AT_FDCWD, "` + filepath.Join(home, ".cache/testapp/ver") + `", O_WRONLY, 0644) = 4`,
		`12345 openat(AT_FDCWD, "` + filepath.Join(home, ".config/testapp/conf.json") + `", O_RDONLY) = 5`,
		`12345 openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 6`,
		`12345 mkdirat(AT_FDCWD, "` + filepath.Join(home, ".config/testapp") + `", 0755) = 0`,
		`12345 openat(AT_FDCWD, "/tmp/somefile", O_WRONLY|O_CREAT, 0644) = 7`,
		`12345 openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 8`,
		`12345 openat(AT_FDCWD, "` + filepath.Join(home, ".cache/testapp/db") + `", O_WRONLY, 0644) = 9`, // duplicate
	}, "\n")

	logFile := filepath.Join(t.TempDir(), "strace.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ParseStraceLog(logFile, false)
	if err != nil {
		t.Fatalf("ParseStraceLog() error: %v", err)
	}

	// Write paths: should have unique home paths only (no /tmp, /proc)
	for _, p := range result.WritePaths {
		if !strings.HasPrefix(p, home+"/") {
			t.Errorf("WritePaths returned path outside home: %q", p)
		}
	}

	// Should not have duplicates in write paths
	seen := make(map[string]bool)
	for _, p := range result.WritePaths {
		if seen[p] {
			t.Errorf("WritePaths returned duplicate: %q", p)
		}
		seen[p] = true
	}

	// Should have the expected write paths
	expectedWrites := map[string]bool{
		filepath.Join(home, ".cache/testapp/db"):  false,
		filepath.Join(home, ".cache/testapp/ver"): false,
		filepath.Join(home, ".config/testapp"):    false,
	}
	for _, p := range result.WritePaths {
		if _, ok := expectedWrites[p]; ok {
			expectedWrites[p] = true
		}
	}
	for p, found := range expectedWrites {
		if !found {
			t.Errorf("WritePaths missing expected path: %q, got: %v", p, result.WritePaths)
		}
	}

	// Should have the expected read paths (only home paths, not /etc or /proc)
	expectedRead := filepath.Join(home, ".config/testapp/conf.json")
	foundRead := false
	for _, p := range result.ReadPaths {
		if p == expectedRead {
			foundRead = true
		}
		if !strings.HasPrefix(p, home+"/") {
			t.Errorf("ReadPaths returned path outside home: %q", p)
		}
	}
	if !foundRead {
		t.Errorf("ReadPaths missing expected path: %q, got: %v", expectedRead, result.ReadPaths)
	}
}

func TestExtractReadPath(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "openat with O_RDONLY",
			line:     `12345 openat(AT_FDCWD, "/home/user/.config/app/conf", O_RDONLY) = 3`,
			expected: "/home/user/.config/app/conf",
		},
		{
			name:     "openat with write flags ignored",
			line:     `12345 openat(AT_FDCWD, "/home/user/file", O_WRONLY|O_CREAT, 0644) = 3`,
			expected: "",
		},
		{
			name:     "non-openat ignored",
			line:     `12345 read(3, "data", 1024) = 5`,
			expected: "",
		},
		{
			name:     "failed openat ignored",
			line:     `12345 openat(AT_FDCWD, "/nonexistent", O_RDONLY) = -1 ENOENT (No such file or directory)`,
			expected: "",
		},
		{
			name:     "directory open ignored",
			line:     `12345 openat(AT_FDCWD, "/home/user", O_RDONLY|O_DIRECTORY) = 3`,
			expected: "",
		},
		{
			name:     "directory open with cloexec ignored",
			line:     `12345 openat(AT_FDCWD, "/home/user/.cache", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractReadPath(tt.line)
			if got != tt.expected {
				t.Errorf("extractReadPath(%q) = %q, want %q", tt.line, got, tt.expected)
			}
		})
	}
}

func TestCheckLearningAvailable(t *testing.T) {
	// This test just verifies the function doesn't panic.
	// The result depends on whether strace is installed on the test system.
	err := CheckLearningAvailable()
	if err != nil {
		t.Logf("strace not available (expected in some CI environments): %v", err)
	}
}
