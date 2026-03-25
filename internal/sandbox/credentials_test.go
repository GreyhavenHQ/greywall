package sandbox

import (
	"strings"
	"testing"
)

func TestDetectCredentials_WellKnown(t *testing.T) {
	env := []string{
		"ANTHROPIC_API_KEY=sk-ant-123",
		"OPENAI_API_KEY=sk-openai-456",
		"PATH=/usr/bin",
		"HOME=/home/test",
	}

	mappings, err := DetectCredentials(env, "test-session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}

	found := map[string]bool{}
	for _, m := range mappings {
		found[m.EnvVar] = true
		if m.RealValue == "" {
			t.Errorf("mapping for %s has empty real value", m.EnvVar)
		}
		if !strings.HasPrefix(m.Placeholder, placeholderPrefix) {
			t.Errorf("placeholder for %s does not start with prefix: %s", m.EnvVar, m.Placeholder)
		}
		if !strings.Contains(m.Placeholder, "test-session") {
			t.Errorf("placeholder for %s does not contain session ID: %s", m.EnvVar, m.Placeholder)
		}
	}
	if !found["ANTHROPIC_API_KEY"] {
		t.Error("ANTHROPIC_API_KEY not detected")
	}
	if !found["OPENAI_API_KEY"] {
		t.Error("OPENAI_API_KEY not detected")
	}
}

func TestDetectCredentials_SuffixPattern(t *testing.T) {
	env := []string{
		"MY_CUSTOM_API_KEY=secret123",
		"SOME_SERVICE_TOKEN=tok456",
		"PLAIN_VARIABLE=hello",
	}

	mappings, err := DetectCredentials(env, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}

	found := map[string]bool{}
	for _, m := range mappings {
		found[m.EnvVar] = true
	}
	if !found["MY_CUSTOM_API_KEY"] {
		t.Error("MY_CUSTOM_API_KEY not detected by suffix pattern")
	}
	if !found["SOME_SERVICE_TOKEN"] {
		t.Error("SOME_SERVICE_TOKEN not detected by suffix pattern")
	}
}

func TestDetectCredentials_EmptyValues(t *testing.T) {
	env := []string{
		"ANTHROPIC_API_KEY=",
		"OPENAI_API_KEY=sk-real",
	}

	mappings, err := DetectCredentials(env, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping (empty value skipped), got %d", len(mappings))
	}
	if mappings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("expected OPENAI_API_KEY, got %s", mappings[0].EnvVar)
	}
}

func TestDetectCredentials_NonCredentialExcluded(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/test",
		"GOOGLE_APPLICATION_CREDENTIALS=/path/to/creds.json",
		"STRIPE_PUBLISHABLE_KEY=pk_test_123",
	}

	mappings, err := DetectCredentials(env, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mappings) != 0 {
		t.Fatalf("expected 0 mappings (all non-credential), got %d", len(mappings))
	}
}

func TestSubstituteEnv(t *testing.T) {
	env := []string{
		"ANTHROPIC_API_KEY=sk-real-key",
		"PATH=/usr/bin",
		"OPENAI_API_KEY=sk-openai-real",
	}

	mappings := []CredentialMapping{
		{EnvVar: "ANTHROPIC_API_KEY", RealValue: "sk-real-key", Placeholder: "greyproxy:credential:v1:test:abc123"},
		{EnvVar: "OPENAI_API_KEY", RealValue: "sk-openai-real", Placeholder: "greyproxy:credential:v1:test:def456"},
	}

	result := SubstituteEnv(env, mappings)

	if len(result) != 3 {
		t.Fatalf("expected 3 env entries, got %d", len(result))
	}

	expected := map[string]string{
		"ANTHROPIC_API_KEY": "greyproxy:credential:v1:test:abc123",
		"PATH":              "/usr/bin",
		"OPENAI_API_KEY":    "greyproxy:credential:v1:test:def456",
	}

	for _, entry := range result {
		idx := strings.Index(entry, "=")
		if idx < 0 {
			t.Errorf("invalid env entry: %s", entry)
			continue
		}
		key := entry[:idx]
		value := entry[idx+1:]
		if expected[key] != value {
			t.Errorf("env %s: expected %q, got %q", key, expected[key], value)
		}
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(id1, "gw-") {
		t.Errorf("session ID should start with gw-: %s", id1)
	}
	if id1 == id2 {
		t.Error("two session IDs should not be equal")
	}
}

func TestGeneratePlaceholder_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		p, err := generatePlaceholder("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[p] {
			t.Fatalf("duplicate placeholder: %s", p)
		}
		seen[p] = true
	}
}

func TestSensitiveGreyproxyFiles(t *testing.T) {
	files := SensitiveGreyproxyFiles()
	if len(files) == 0 {
		t.Fatal("expected sensitive files list to be non-empty")
	}

	hasSessionKey := false
	hasCaKey := false
	for _, f := range files {
		if strings.Contains(f, "session.key") {
			hasSessionKey = true
		}
		if strings.Contains(f, "ca-key.pem") {
			hasCaKey = true
		}
	}
	if !hasSessionKey {
		t.Error("missing session.key in sensitive files")
	}
	if !hasCaKey {
		t.Error("missing ca-key.pem in sensitive files")
	}
}

func TestMatchesSuffixPattern(t *testing.T) {
	tests := []struct {
		key    string
		expect bool
	}{
		{"MY_API_KEY", true},
		{"SOME_TOKEN", true},
		{"DB_PASSWORD", true},
		{"MY_SECRET", true},
		{"MY_ACCESS_TOKEN", true},
		{"NORMAL_VAR", false},
		{"MY_SETTING", false},
		{"API_KEY_NAME", false}, // KEY_NAME does not end with _API_KEY
	}

	for _, tt := range tests {
		got := matchesSuffixPattern(tt.key)
		if got != tt.expect {
			t.Errorf("matchesSuffixPattern(%q) = %v, want %v", tt.key, got, tt.expect)
		}
	}
}
