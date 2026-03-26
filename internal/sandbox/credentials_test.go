package sandbox

import (
	"os"
	"path/filepath"
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

	mappings, err := DetectCredentials(env, "test-session", nil, nil)
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

	mappings, err := DetectCredentials(env, "test", nil, nil)
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

	mappings, err := DetectCredentials(env, "test", nil, nil)
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

	mappings, err := DetectCredentials(env, "test", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mappings) != 0 {
		t.Fatalf("expected 0 mappings (all non-credential), got %d", len(mappings))
	}
}

func TestDetectCredentials_ExtraVars(t *testing.T) {
	env := []string{
		"MY_CUSTOM_THING=secret-value",
		"PLAIN_VARIABLE=hello",
	}

	// Without extraVars, MY_CUSTOM_THING is not detected (no matching suffix)
	mappings, err := DetectCredentials(env, "test", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Fatalf("expected 0 mappings without extraVars, got %d", len(mappings))
	}

	// With extraVars, it is detected
	mappings, err = DetectCredentials(env, "test", []string{"MY_CUSTOM_THING"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping with extraVars, got %d", len(mappings))
	}
	if mappings[0].EnvVar != "MY_CUSTOM_THING" {
		t.Errorf("expected MY_CUSTOM_THING, got %s", mappings[0].EnvVar)
	}
	if mappings[0].RealValue != "secret-value" {
		t.Errorf("expected secret-value, got %s", mappings[0].RealValue)
	}
}

func TestDetectCredentials_IgnoreVars(t *testing.T) {
	env := []string{
		"ANTHROPIC_API_KEY=sk-ant-123",
		"MY_INTERNAL_TOKEN=internal-value",
		"OPENAI_API_KEY=sk-openai-456",
	}

	// Without ignore, all three are detected
	mappings, err := DetectCredentials(env, "test", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 3 {
		t.Fatalf("expected 3 mappings without ignore, got %d", len(mappings))
	}

	// With ignore, ANTHROPIC_API_KEY and MY_INTERNAL_TOKEN are excluded
	mappings, err = DetectCredentials(env, "test", nil, []string{"ANTHROPIC_API_KEY", "MY_INTERNAL_TOKEN"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping with ignore, got %d", len(mappings))
	}
	if mappings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("expected OPENAI_API_KEY, got %s", mappings[0].EnvVar)
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

func TestSubstituteEnv_AppendsNewVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
	}

	mappings := []CredentialMapping{
		{EnvVar: "ANTHROPIC_API_KEY", Placeholder: "greyproxy:credential:v1:global:abc123"},
	}

	result := SubstituteEnv(env, mappings)

	if len(result) != 2 {
		t.Fatalf("expected 2 env entries, got %d: %v", len(result), result)
	}

	found := false
	for _, entry := range result {
		if entry == "ANTHROPIC_API_KEY=greyproxy:credential:v1:global:abc123" {
			found = true
		}
	}
	if !found {
		t.Errorf("ANTHROPIC_API_KEY not appended: %v", result)
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

func TestSubstituteEnvFileContent_ExactValueMatch(t *testing.T) {
	data := []byte("OPENAI_API_KEY=sk-real-key\nPATH=/usr/bin\nDB_PASSWORD=secret123\n")
	valueLookup := map[string]string{
		"sk-real-key": "placeholder-1",
		"secret123":   "placeholder-2",
	}

	result, count := substituteEnvFileContent(data, nil, valueLookup)
	if count != 2 {
		t.Fatalf("expected 2 substitutions, got %d", count)
	}

	lines := strings.Split(string(result), "\n")
	if lines[0] != "OPENAI_API_KEY=placeholder-1" {
		t.Errorf("line 0: got %q", lines[0])
	}
	if lines[1] != "PATH=/usr/bin" {
		t.Errorf("line 1: got %q", lines[1])
	}
	if lines[2] != "DB_PASSWORD=placeholder-2" {
		t.Errorf("line 2: got %q", lines[2])
	}
}

func TestSubstituteEnvFileContent_KeyMatch(t *testing.T) {
	// .env file has a different value than the environment variable,
	// but key-based matching should still replace it.
	data := []byte("ANTHROPIC_API_KEY=hello\nPLAIN=world\n")
	keyLookup := map[string]string{
		"ANTHROPIC_API_KEY": "greyproxy:credential:v1:test:abc",
	}

	result, count := substituteEnvFileContent(data, keyLookup, nil)
	if count != 1 {
		t.Fatalf("expected 1 substitution, got %d", count)
	}

	lines := strings.Split(string(result), "\n")
	if lines[0] != "ANTHROPIC_API_KEY=greyproxy:credential:v1:test:abc" {
		t.Errorf("line 0: got %q", lines[0])
	}
	if lines[1] != "PLAIN=world" {
		t.Errorf("line 1 should be unchanged: got %q", lines[1])
	}
}

func TestSubstituteEnvFileContent_KeyMatchWithExportPrefix(t *testing.T) {
	data := []byte("export ANTHROPIC_API_KEY=hello\n")
	keyLookup := map[string]string{
		"ANTHROPIC_API_KEY": "placeholder",
	}

	result, count := substituteEnvFileContent(data, keyLookup, nil)
	if count != 1 {
		t.Fatalf("expected 1 substitution, got %d", count)
	}

	lines := strings.Split(string(result), "\n")
	if lines[0] != "export ANTHROPIC_API_KEY=placeholder" {
		t.Errorf("line 0: got %q", lines[0])
	}
}

func TestSubstituteEnvFileContent_KeyMatchPriorityOverValue(t *testing.T) {
	// When both key and value match, key-based placeholder should win.
	data := []byte("ANTHROPIC_API_KEY=sk-real\n")
	keyLookup := map[string]string{
		"ANTHROPIC_API_KEY": "key-placeholder",
	}
	valueLookup := map[string]string{
		"sk-real": "value-placeholder",
	}

	result, count := substituteEnvFileContent(data, keyLookup, valueLookup)
	if count != 1 {
		t.Fatalf("expected 1 substitution, got %d", count)
	}

	lines := strings.Split(string(result), "\n")
	if lines[0] != "ANTHROPIC_API_KEY=key-placeholder" {
		t.Errorf("key-based match should take priority: got %q", lines[0])
	}
}

func TestSubstituteEnvFileContent_QuotedValues(t *testing.T) {
	data := []byte(`OPENAI_API_KEY="sk-real-key"
DB_PASSWORD='secret123'
`)
	keyLookup := map[string]string{
		"OPENAI_API_KEY": "placeholder-1",
		"DB_PASSWORD":    "placeholder-2",
	}

	result, count := substituteEnvFileContent(data, keyLookup, nil)
	if count != 2 {
		t.Fatalf("expected 2 substitutions, got %d", count)
	}

	lines := strings.Split(string(result), "\n")
	if lines[0] != `OPENAI_API_KEY="placeholder-1"` {
		t.Errorf("line 0: got %q", lines[0])
	}
	if lines[1] != `DB_PASSWORD='placeholder-2'` {
		t.Errorf("line 1: got %q", lines[1])
	}
}

func TestSubstituteEnvFileContent_CommentsAndBlanks(t *testing.T) {
	data := []byte("# This is a comment\n\nOPENAI_API_KEY=sk-real\n# Another comment\nPLAIN=hello\n")
	keyLookup := map[string]string{
		"OPENAI_API_KEY": "placeholder",
	}

	result, count := substituteEnvFileContent(data, keyLookup, nil)
	if count != 1 {
		t.Fatalf("expected 1 substitution, got %d", count)
	}

	lines := strings.Split(string(result), "\n")
	if lines[0] != "# This is a comment" {
		t.Errorf("comment not preserved: got %q", lines[0])
	}
	if lines[1] != "" {
		t.Errorf("blank line not preserved: got %q", lines[1])
	}
	if lines[2] != "OPENAI_API_KEY=placeholder" {
		t.Errorf("substitution failed: got %q", lines[2])
	}
	if lines[4] != "PLAIN=hello" {
		t.Errorf("non-credential line modified: got %q", lines[4])
	}
}

func TestSubstituteEnvFileContent_InlineReplacement(t *testing.T) {
	data := []byte("DATABASE_URL=postgres://user:secret123@host/db\n")
	valueLookup := map[string]string{
		"secret123": "placeholder",
	}

	result, count := substituteEnvFileContent(data, nil, valueLookup)
	if count != 1 {
		t.Fatalf("expected 1 substitution, got %d", count)
	}

	expected := "DATABASE_URL=postgres://user:placeholder@host/db\n" //nolint:gosec // test data, not real credentials
	if string(result) != expected {
		t.Errorf("got %q, want %q", string(result), expected)
	}
}

func TestSubstituteEnvFileContent_NoMatch(t *testing.T) {
	data := []byte("PLAIN_VAR=hello\nANOTHER=world\n")
	valueLookup := map[string]string{
		"sk-real": "placeholder",
	}

	result, count := substituteEnvFileContent(data, nil, valueLookup)
	if count != 0 {
		t.Fatalf("expected 0 substitutions, got %d", count)
	}
	if string(result) != string(data) {
		t.Errorf("content should be unchanged")
	}
}

func TestRewriteEnvFiles(t *testing.T) {
	// Create a temp dir with a .env file.
	tmpDir := t.TempDir()
	envContent := "OPENAI_API_KEY=sk-real-key\nPLAIN=hello\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	credKeys := map[string]bool{"OPENAI_API_KEY": true}

	result, err := RewriteEnvFiles(tmpDir, "test-session", credKeys, false)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	envPath := filepath.Join(tmpDir, ".env")
	tmpPath, ok := result.RewrittenFiles[envPath]
	if !ok {
		t.Fatalf(".env not in rewritten map: %v", result.RewrittenFiles)
	}

	// Read the rewritten file.
	data, err := os.ReadFile(tmpPath) //nolint:gosec // test reads a temp file by variable path
	if err != nil {
		t.Fatalf("failed to read rewritten file: %v", err)
	}

	if !strings.Contains(string(data), placeholderPrefix) {
		t.Errorf("rewritten file should contain placeholder prefix: %s", string(data))
	}
	if strings.Contains(string(data), "sk-real-key") {
		t.Errorf("rewritten file should not contain real key: %s", string(data))
	}
	if !strings.Contains(string(data), "PLAIN=hello") {
		t.Errorf("rewritten file should preserve non-credential lines: %s", string(data))
	}

	// Verify file mappings were generated.
	if len(result.FileMappings) != 1 {
		t.Fatalf("expected 1 file mapping, got %d", len(result.FileMappings))
	}
	fm := result.FileMappings[0]
	if fm.EnvVar != "OPENAI_API_KEY" {
		t.Errorf("expected EnvVar OPENAI_API_KEY, got %s", fm.EnvVar)
	}
	if fm.RealValue != "sk-real-key" {
		t.Errorf("expected RealValue sk-real-key, got %s", fm.RealValue)
	}
	if !strings.HasPrefix(fm.Placeholder, placeholderPrefix) {
		t.Errorf("placeholder should start with prefix: %s", fm.Placeholder)
	}

	// Cleanup.
	CleanupRewrittenFiles(result.RewrittenFiles)
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should be cleaned up")
	}
}

func TestRewriteEnvFiles_DifferentValuesPerFile(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("ANTHROPIC_API_KEY=val1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env.local"), []byte("ANTHROPIC_API_KEY=val2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	credKeys := map[string]bool{"ANTHROPIC_API_KEY": true}

	result, err := RewriteEnvFiles(tmpDir, "test-session", credKeys, false)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Both files should be rewritten.
	if len(result.RewrittenFiles) != 2 {
		t.Fatalf("expected 2 rewritten files, got %d", len(result.RewrittenFiles))
	}

	// Should have 2 file mappings with different real values and different placeholders.
	if len(result.FileMappings) != 2 {
		t.Fatalf("expected 2 file mappings, got %d", len(result.FileMappings))
	}

	values := make(map[string]string) // realValue -> placeholder
	for _, fm := range result.FileMappings {
		if fm.EnvVar != "ANTHROPIC_API_KEY" {
			t.Errorf("unexpected EnvVar: %s", fm.EnvVar)
		}
		values[fm.RealValue] = fm.Placeholder
	}

	if _, ok := values["val1"]; !ok {
		t.Error("missing mapping for val1 (.env)")
	}
	if _, ok := values["val2"]; !ok {
		t.Error("missing mapping for val2 (.env.local)")
	}

	// Placeholders must be different.
	if values["val1"] == values["val2"] {
		t.Error("placeholders for different values should be unique")
	}

	// Verify rewritten file contents have different placeholders.
	for origPath, tmpPath := range result.RewrittenFiles {
		data, err := os.ReadFile(tmpPath) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		if strings.Contains(content, "val1") || strings.Contains(content, "val2") {
			t.Errorf("%s still contains real value: %s", origPath, content)
		}
		if !strings.Contains(content, placeholderPrefix) {
			t.Errorf("%s missing placeholder: %s", origPath, content)
		}
	}

	CleanupRewrittenFiles(result.RewrittenFiles)
}

func TestRewriteEnvFiles_NoCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("PLAIN=hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	credKeys := map[string]bool{"OPENAI_API_KEY": true}

	// .env has no matching credential keys; should return nil.
	result, err := RewriteEnvFiles(tmpDir, "test", credKeys, false)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil when no credentials match, got %v", result)
	}
}

func TestRewriteEnvFiles_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	credKeys := map[string]bool{"OPENAI_API_KEY": true}

	result, err := RewriteEnvFiles(tmpDir, "test", credKeys, false)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil when no .env files exist, got %v", result)
	}
}

func TestRewriteEnvFiles_EmptyKeys(t *testing.T) {
	result, err := RewriteEnvFiles("/tmp", "test", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil for empty keys")
	}
}

func TestRewriteEnvFiles_EmptyCwd(t *testing.T) {
	credKeys := map[string]bool{"KEY": true}
	result, err := RewriteEnvFiles("", "test", credKeys, false)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil for empty cwd")
	}
}

func TestParseEnvFile(t *testing.T) {
	data := []byte("# comment\nKEY1=val1\nexport KEY2=\"val2\"\nKEY3='val3'\n\nPLAIN=hello\n")
	result := parseEnvFile(data)

	if len(result) != 4 {
		t.Fatalf("expected 4 entries, got %d: %+v", len(result), result)
	}

	expected := []envKeyValue{
		{key: "KEY1", value: "val1"},
		{key: "KEY2", value: "val2"},
		{key: "KEY3", value: "val3"},
		{key: "PLAIN", value: "hello"},
	}

	for i, want := range expected {
		if result[i].key != want.key || result[i].value != want.value {
			t.Errorf("entry %d: got {%s, %s}, want {%s, %s}", i, result[i].key, result[i].value, want.key, want.value)
		}
	}
}
