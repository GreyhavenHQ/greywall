package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSanitizeTemplateName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"opencode", "opencode"},
		{"my-app", "my-app"},
		{"my_app", "my_app"},
		{"my.app", "my.app"},
		{"my app", "my_app"},
		{"/usr/bin/opencode", "usr_bin_opencode"},
		{"my@app!v2", "my_app_v2"},
		{"", "unknown"},
		{"///", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SanitizeTemplateName(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeTemplateName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestLearnedTemplatePath(t *testing.T) {
	path := LearnedTemplatePath("opencode")
	if !strings.HasSuffix(path, "/learned/opencode.json") {
		t.Errorf("LearnedTemplatePath(\"opencode\") = %q, expected suffix /learned/opencode.json", path)
	}
}

func TestFindApplicationDirectory(t *testing.T) {
	home := "/home/testuser"
	tests := []struct {
		path     string
		expected string
	}{
		{"/home/testuser/.cache/opencode/db/main.sqlite", "/home/testuser/.cache/opencode"},
		{"/home/testuser/.cache/opencode/version", "/home/testuser/.cache/opencode"},
		{"/home/testuser/.config/opencode/settings.json", "/home/testuser/.config/opencode"},
		{"/home/testuser/.local/share/myapp/data", "/home/testuser/.local/share/myapp"},
		{"/home/testuser/.local/state/myapp/log", "/home/testuser/.local/state/myapp"},
		// Not under a well-known parent
		{"/home/testuser/documents/file.txt", ""},
		{"/home/testuser/.cache", ""},
		// Different home
		{"/other/user/.cache/app/file", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := findApplicationDirectory(tt.path, home)
			if got != tt.expected {
				t.Errorf("findApplicationDirectory(%q, %q) = %q, want %q", tt.path, home, got, tt.expected)
			}
		})
	}
}

func TestCollapsePaths(t *testing.T) {
	// Temporarily override home for testing
	t.Setenv("HOME", "/home/testuser")

	tests := []struct {
		name        string
		paths       []string
		contains    []string // paths that should be in the result
		notContains []string // paths that must NOT be in the result
	}{
		{
			name: "multiple paths under same app dir",
			paths: []string{
				"/home/testuser/.cache/opencode/db/main.sqlite",
				"/home/testuser/.cache/opencode/version",
			},
			contains: []string{"/home/testuser/.cache/opencode"},
		},
		{
			name:     "empty input",
			paths:    nil,
			contains: nil,
		},
		{
			name: "single path uses parent dir",
			paths: []string{
				"/home/testuser/.cache/opencode/version",
			},
			contains: []string{"/home/testuser/.cache/opencode"},
		},
		{
			name: "paths from different app dirs",
			paths: []string{
				"/home/testuser/.cache/opencode/db",
				"/home/testuser/.cache/opencode/version",
				"/home/testuser/.config/opencode/settings.json",
			},
			contains: []string{
				"/home/testuser/.cache/opencode",
				"/home/testuser/.config/opencode",
			},
		},
		{
			name: "files directly under home stay as exact paths",
			paths: []string{
				"/home/testuser/.gitignore",
				"/home/testuser/.npmrc",
			},
			contains: []string{
				"/home/testuser/.gitignore",
				"/home/testuser/.npmrc",
			},
			notContains: []string{"/home/testuser"},
		},
		{
			name: "mix of home files and app dir paths",
			paths: []string{
				"/home/testuser/.gitignore",
				"/home/testuser/.cache/opencode/db/main.sqlite",
				"/home/testuser/.cache/opencode/version",
				"/home/testuser/.npmrc",
			},
			contains: []string{
				"/home/testuser/.gitignore",
				"/home/testuser/.npmrc",
				"/home/testuser/.cache/opencode",
			},
			notContains: []string{"/home/testuser"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CollapsePaths(tt.paths)
			if tt.contains == nil {
				if got != nil {
					t.Errorf("CollapsePaths() = %v, want nil", got)
				}
				return
			}
			for _, want := range tt.contains {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("CollapsePaths() = %v, missing expected path %q", got, want)
				}
			}
			for _, bad := range tt.notContains {
				for _, g := range got {
					if g == bad {
						t.Errorf("CollapsePaths() = %v, should NOT contain %q", got, bad)
					}
				}
			}
		})
	}
}

func TestIsDefaultWritablePath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/dev/null", true},
		{"/dev/stdout", true},
		{"/tmp/somefile", false}, // /tmp is tmpfs inside sandbox, not host /tmp
		{"/home/user/file", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isDefaultWritablePath(tt.path)
			if got != tt.expected {
				t.Errorf("isDefaultWritablePath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestIsSensitivePath(t *testing.T) {
	home := "/home/testuser"
	tests := []struct {
		path     string
		expected bool
	}{
		{"/home/testuser/.bashrc", true},
		{"/home/testuser/.gitconfig", true},
		{"/home/testuser/.ssh/id_rsa", true},
		{"/home/testuser/.ssh/known_hosts", true},
		{"/home/testuser/.gnupg/secring.gpg", true},
		{"/home/testuser/.env", true},
		{"/home/testuser/project/.env.local", true},
		{"/home/testuser/.cache/opencode/db", false},
		{"/home/testuser/documents/readme.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isSensitivePath(tt.path, home)
			if got != tt.expected {
				t.Errorf("isSensitivePath(%q, %q) = %v, want %v", tt.path, home, got, tt.expected)
			}
		})
	}
}

func TestDeduplicateSubPaths(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected []string
	}{
		{
			name:     "removes sub-paths",
			paths:    []string{"/home/user/.cache", "/home/user/.cache/opencode"},
			expected: []string{"/home/user/.cache"},
		},
		{
			name:     "keeps independent paths",
			paths:    []string{"/home/user/.cache/opencode", "/home/user/.config/opencode"},
			expected: []string{"/home/user/.cache/opencode", "/home/user/.config/opencode"},
		},
		{
			name:     "empty",
			paths:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateSubPaths(tt.paths)
			if len(got) != len(tt.expected) {
				t.Errorf("deduplicateSubPaths(%v) = %v, want %v", tt.paths, got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("deduplicateSubPaths(%v)[%d] = %q, want %q", tt.paths, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestGetDangerousFilePatterns(t *testing.T) {
	patterns := getDangerousFilePatterns()
	if len(patterns) == 0 {
		t.Error("getDangerousFilePatterns() returned empty list")
	}
	// Check some expected patterns
	found := false
	for _, p := range patterns {
		if p == "~/.bashrc" {
			found = true
			break
		}
	}
	if !found {
		t.Error("getDangerousFilePatterns() missing ~/.bashrc")
	}
}

func TestGetSensitiveReadPatterns(t *testing.T) {
	patterns := getSensitiveReadPatterns()
	if len(patterns) == 0 {
		t.Error("getSensitiveReadPatterns() returned empty list")
	}
	found := false
	for _, p := range patterns {
		if p == "~/.ssh/id_*" {
			found = true
			break
		}
	}
	if !found {
		t.Error("getSensitiveReadPatterns() missing ~/.ssh/id_*")
	}
}

func TestToTildePath(t *testing.T) {
	tests := []struct {
		path     string
		home     string
		expected string
	}{
		{"/home/user/.cache/opencode", "/home/user", "~/.cache/opencode"},
		{"/other/path", "/home/user", "/other/path"},
		{"/home/user/.cache/opencode", "", "/home/user/.cache/opencode"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := toTildePath(tt.path, tt.home)
			if got != tt.expected {
				t.Errorf("toTildePath(%q, %q) = %q, want %q", tt.path, tt.home, got, tt.expected)
			}
		})
	}
}

func TestListLearnedTemplates(t *testing.T) {
	// Use a temp dir to isolate from real user config
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Initially empty
	templates, err := ListLearnedTemplates()
	if err != nil {
		t.Fatalf("ListLearnedTemplates() error: %v", err)
	}
	if len(templates) != 0 {
		t.Errorf("expected empty list, got %v", templates)
	}

	// Create some templates
	dir := LearnedTemplateDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "opencode.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "myapp.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notjson.txt"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	templates, err = ListLearnedTemplates()
	if err != nil {
		t.Fatalf("ListLearnedTemplates() error: %v", err)
	}
	if len(templates) != 2 {
		t.Errorf("expected 2 templates, got %d: %v", len(templates), templates)
	}

	names := make(map[string]bool)
	for _, tmpl := range templates {
		names[tmpl.Name] = true
	}
	if !names["opencode"] {
		t.Error("missing template 'opencode'")
	}
	if !names["myapp"] {
		t.Error("missing template 'myapp'")
	}
}

func TestBuildTemplate(t *testing.T) {
	allowRead := []string{"~/external-data"}
	allowWrite := []string{".", "~/.cache/opencode", "~/.config/opencode"}
	result := buildTemplate("opencode", allowRead, allowWrite)

	// Check header comments
	if !strings.Contains(result, `Learned template for "opencode"`) {
		t.Error("template missing header comment with command name")
	}
	if !strings.Contains(result, "greywall --learning -- opencode") {
		t.Error("template missing generation command")
	}
	if !strings.Contains(result, "Review and adjust paths as needed") {
		t.Error("template missing review comment")
	}

	// Check content
	if !strings.Contains(result, `"allowRead"`) {
		t.Error("template missing allowRead field")
	}
	if !strings.Contains(result, `"~/external-data"`) {
		t.Error("template missing expected allowRead path")
	}
	if !strings.Contains(result, `"allowWrite"`) {
		t.Error("template missing allowWrite field")
	}
	if !strings.Contains(result, `"~/.cache/opencode"`) {
		t.Error("template missing expected allowWrite path")
	}
	if !strings.Contains(result, `"denyWrite"`) {
		t.Error("template missing denyWrite field")
	}
	if !strings.Contains(result, `"denyRead"`) {
		t.Error("template missing denyRead field")
	}
	// Check .env patterns are included in denyRead
	if !strings.Contains(result, `".env"`) {
		t.Error("template missing .env in denyRead")
	}
	if !strings.Contains(result, `".env.*"`) {
		t.Error("template missing .env.* in denyRead")
	}
}

func TestBuildTemplateNoAllowRead(t *testing.T) {
	result := buildTemplate("simple-cmd", nil, []string{"."})

	// When allowRead is nil, it should be omitted from JSON
	if strings.Contains(result, `"allowRead"`) {
		t.Error("template should omit allowRead when nil")
	}
}

func TestGenerateLearnedTemplate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("strace log parsing is only available on Linux")
	}
	// Create a temp dir for templates
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Create a fake trace result (simulating what ParseStraceLog would return)
	home, _ := os.UserHomeDir()
	result := &TraceResult{
		WritePaths: []string{
			filepath.Join(home, ".cache/testapp/db.sqlite"),
			filepath.Join(home, ".cache/testapp/version"),
			filepath.Join(home, ".config/testapp"),
		},
	}

	templatePath, err := GenerateLearnedTemplate(result, "testapp", false)
	if err != nil {
		t.Fatalf("GenerateLearnedTemplate() error: %v", err)
	}

	if templatePath == "" {
		t.Fatal("GenerateLearnedTemplate() returned empty path")
	}

	// Read and verify template
	data, err := os.ReadFile(templatePath) //nolint:gosec // reading test-generated template file
	if err != nil {
		t.Fatalf("failed to read template: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "testapp") {
		t.Error("template doesn't contain command name")
	}
	if !strings.Contains(content, "allowWrite") {
		t.Error("template doesn't contain allowWrite")
	}
}
