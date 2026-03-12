package profiles_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
	_ "github.com/GreyhavenHQ/greywall/internal/profiles/agents"      // register all agents
	_ "github.com/GreyhavenHQ/greywall/internal/profiles/toolchains" // register all toolchains
)

func TestIsKnownAgent(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"claude", "claude"},
		{"claude-code", "claude"},
		{"cursor", "cursor"},
		{"cursor-agent", "cursor"},
		{"kilocode", "kilo"},
		{"ls", ""},
		{"unknown-tool", ""},
	}
	for _, tt := range tests {
		if got := profiles.IsKnownAgent(tt.cmd); got != tt.want {
			t.Errorf("IsKnownAgent(%q) = %q, want %q", tt.cmd, got, tt.want)
		}
	}
}

func TestIsAdHocCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"ls", true},
		{"curl", true},
		{"git", true},
		{"make", true},
		{"npm", false},   // toolchain, not ad-hoc
		{"uv", false},    // toolchain, not ad-hoc
		{"cargo", false}, // toolchain, not ad-hoc
		{"claude", false},
		{"my-custom-tool", false},
	}
	for _, tt := range tests {
		if got := profiles.IsAdHocCommand(tt.cmd); got != tt.want {
			t.Errorf("IsAdHocCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

func TestBaseProfile(t *testing.T) {
	profile := profiles.BaseProfile()
	if profile == nil {
		t.Fatal("BaseProfile() returned nil")
	}
	if len(profile.Filesystem.AllowRead) == 0 {
		t.Error("BaseProfile has no AllowRead paths")
	}
	if len(profile.Filesystem.DenyRead) == 0 {
		t.Error("BaseProfile has no DenyRead paths")
	}
	if len(profile.Filesystem.DenyWrite) == 0 {
		t.Error("BaseProfile has no DenyWrite paths")
	}
	if profile.Command.UseDefaults == nil || !*profile.Command.UseDefaults {
		t.Error("BaseProfile should have UseDefaults=true")
	}
}

func TestGetAgentProfile(t *testing.T) {
	for _, name := range profiles.AvailableAgents() {
		profile := profiles.GetAgentProfile(name)
		if profile == nil {
			t.Errorf("GetAgentProfile(%q) returned nil", name)
			continue
		}

		if profiles.IsToolchain(name) {
			// Toolchain profiles should NOT have base paths
			for _, p := range profile.Filesystem.AllowRead {
				if p == "~/.gitconfig" {
					t.Errorf("toolchain %q should not have base path ~/.gitconfig", name)
				}
			}
		} else {
			// Agent profiles should have base paths merged in
			hasGitConfig := false
			for _, p := range profile.Filesystem.AllowRead {
				if p == "~/.gitconfig" {
					hasGitConfig = true
					break
				}
			}
			if !hasGitConfig {
				t.Errorf("GetAgentProfile(%q) missing base path ~/.gitconfig in AllowRead", name)
			}
		}
	}

	if profile := profiles.GetAgentProfile("nonexistent"); profile != nil {
		t.Error("GetAgentProfile(nonexistent) should return nil")
	}
}

func TestAvailableAgents(t *testing.T) {
	agents := profiles.AvailableAgents()
	if len(agents) == 0 {
		t.Fatal("AvailableAgents() returned empty list")
	}
	// Check for duplicates
	seen := make(map[string]bool)
	for _, a := range agents {
		if seen[a] {
			t.Errorf("AvailableAgents() contains duplicate: %s", a)
		}
		seen[a] = true
	}
}

func TestPromptFirstRun(t *testing.T) {
	var buf bytes.Buffer

	// Test "Y" (default/enter)
	resp := profiles.PromptFirstRun("claude", &buf, strings.NewReader("\n"))
	if resp != profiles.PromptYes {
		t.Errorf("empty input should return PromptYes, got %d", resp)
	}

	buf.Reset()
	resp = profiles.PromptFirstRun("claude", &buf, strings.NewReader("y\n"))
	if resp != profiles.PromptYes {
		t.Errorf("'y' should return PromptYes, got %d", resp)
	}

	buf.Reset()
	resp = profiles.PromptFirstRun("claude", &buf, strings.NewReader("yes\n"))
	if resp != profiles.PromptYes {
		t.Errorf("'yes' should return PromptYes, got %d", resp)
	}

	// Test "n"
	buf.Reset()
	resp = profiles.PromptFirstRun("claude", &buf, strings.NewReader("n\n"))
	if resp != profiles.PromptNo {
		t.Errorf("'n' should return PromptNo, got %d", resp)
	}

	// Test "never"
	buf.Reset()
	resp = profiles.PromptFirstRun("claude", &buf, strings.NewReader("never\n"))
	if resp != profiles.PromptNever {
		t.Errorf("'never' should return PromptNever, got %d", resp)
	}

	// Test EOF (no input)
	buf.Reset()
	resp = profiles.PromptFirstRun("claude", &buf, strings.NewReader(""))
	if resp != profiles.PromptNo {
		t.Errorf("EOF should return PromptNo, got %d", resp)
	}
}

func TestPreferences(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Load empty preferences
	prefs, err := profiles.LoadPreferences()
	if err != nil {
		t.Fatalf("LoadPreferences() error: %v", err)
	}
	if prefs.IsPromptSuppressed("claude") {
		t.Error("fresh preferences should not suppress claude")
	}

	// Add suppression
	if err := profiles.AddSuppression("claude"); err != nil {
		t.Fatalf("AddSuppression() error: %v", err)
	}

	// Reload and verify
	prefs, err = profiles.LoadPreferences()
	if err != nil {
		t.Fatalf("LoadPreferences() error: %v", err)
	}
	if !prefs.IsPromptSuppressed("claude") {
		t.Error("claude should be suppressed after AddSuppression")
	}
	if prefs.IsPromptSuppressed("codex") {
		t.Error("codex should not be suppressed")
	}

	// Add same suppression again (no duplicates)
	if err := profiles.AddSuppression("claude"); err != nil {
		t.Fatalf("AddSuppression() error: %v", err)
	}
	prefs, err = profiles.LoadPreferences()
	if err != nil {
		t.Fatalf("LoadPreferences() error: %v", err)
	}
	count := 0
	for _, s := range prefs.SuppressProfilePrompt {
		if s == "claude" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 entry for claude, got %d", count)
	}
}

func TestSaveAsTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	profile := profiles.GetAgentProfile("claude")
	if profile == nil {
		t.Fatal("GetAgentProfile(claude) returned nil")
	}

	if err := profiles.SaveAsTemplate(profile, "claude", false); err != nil {
		t.Fatalf("SaveAsTemplate() error: %v", err)
	}

	// Read back and verify format
	data, err := os.ReadFile(filepath.Join(tmpDir, "greywall", "learned", "claude.json"))
	if err != nil {
		t.Fatalf("failed to read saved template: %v", err)
	}
	content := string(data)

	// Must NOT contain top-level keys that aren't part of learned templates
	for _, forbidden := range []string{`"network"`, `"command"`, `"ssh"`, `"allowPty"`} {
		if strings.Contains(content, forbidden) {
			t.Errorf("saved template should not contain %s, got:\n%s", forbidden, content)
		}
	}

	// Must contain filesystem paths
	if !strings.Contains(content, `"allowRead"`) {
		t.Error("saved template missing allowRead")
	}
	if !strings.Contains(content, `"allowWrite"`) {
		t.Error("saved template missing allowWrite")
	}
	if !strings.Contains(content, `"~/.claude"`) {
		t.Error("saved template missing claude-specific path ~/.claude")
	}

	// Must be loadable by config.Load
	cfg, err := config.Load(filepath.Join(tmpDir, "greywall", "learned", "claude.json"))
	if err != nil {
		t.Fatalf("saved template failed config.Load: %v", err)
	}
	if cfg == nil {
		t.Fatal("config.Load returned nil for saved template")
	}
}

func TestListAvailableProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	available := profiles.ListAvailableProfiles()
	if len(available) == 0 {
		t.Fatal("ListAvailableProfiles() returned empty when no templates saved")
	}

	// Simulate saving a template for claude
	learnedDir := filepath.Join(tmpDir, "greywall", "learned")
	if err := os.MkdirAll(learnedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(learnedDir, "claude.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	available = profiles.ListAvailableProfiles()
	for _, a := range available {
		if a == "claude" {
			t.Error("claude should not be in available list when template exists")
		}
	}
}
