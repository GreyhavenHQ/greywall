//go:build darwin

package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeEsloggerLine builds a single JSON line matching real eslogger output format.
// event_type is an int, and event data is nested under event.{eventName}.
func makeEsloggerLine(eventName string, eventTypeInt int, pid int, eventData interface{}) string {
	eventJSON, _ := json.Marshal(eventData)
	ev := map[string]interface{}{
		"event_type": eventTypeInt,
		"process": map[string]interface{}{
			"audit_token": map[string]interface{}{
				"pid": pid,
			},
			"executable": map[string]interface{}{
				"path":           "/usr/bin/test",
				"path_truncated": false,
			},
			"ppid": 1,
		},
		"event": map[string]json.RawMessage{
			eventName: json.RawMessage(eventJSON),
		},
	}
	data, _ := json.Marshal(ev)
	return string(data)
}

func TestClassifyEsloggerEvent(t *testing.T) {
	tests := []struct {
		name        string
		eventName   string
		eventData   interface{}
		expectPaths []string
		expectClass opClass
	}{
		{
			name:      "open read-only",
			eventName: "open",
			eventData: map[string]interface{}{
				"file":  map[string]interface{}{"path": "/Users/test/file.txt", "path_truncated": false},
				"fflag": 0x0001, // FREAD only
			},
			expectPaths: []string{"/Users/test/file.txt"},
			expectClass: opRead,
		},
		{
			name:      "open with write flag",
			eventName: "open",
			eventData: map[string]interface{}{
				"file":  map[string]interface{}{"path": "/Users/test/file.txt", "path_truncated": false},
				"fflag": 0x0003, // FREAD | FWRITE
			},
			expectPaths: []string{"/Users/test/file.txt"},
			expectClass: opWrite,
		},
		{
			name:      "create event with existing_file",
			eventName: "create",
			eventData: map[string]interface{}{
				"destination_type": 0,
				"destination": map[string]interface{}{
					"existing_file": map[string]interface{}{"path": "/Users/test/new.txt", "path_truncated": false},
				},
			},
			expectPaths: []string{"/Users/test/new.txt"},
			expectClass: opWrite,
		},
		{
			name:      "write event uses target",
			eventName: "write",
			eventData: map[string]interface{}{
				"target": map[string]interface{}{"path": "/Users/test/data.db", "path_truncated": false},
			},
			expectPaths: []string{"/Users/test/data.db"},
			expectClass: opWrite,
		},
		{
			name:      "unlink event uses target",
			eventName: "unlink",
			eventData: map[string]interface{}{
				"target": map[string]interface{}{"path": "/Users/test/old.txt", "path_truncated": false},
			},
			expectPaths: []string{"/Users/test/old.txt"},
			expectClass: opWrite,
		},
		{
			name:      "truncate event uses target",
			eventName: "truncate",
			eventData: map[string]interface{}{
				"target": map[string]interface{}{"path": "/Users/test/trunc.log", "path_truncated": false},
			},
			expectPaths: []string{"/Users/test/trunc.log"},
			expectClass: opWrite,
		},
		{
			name:      "rename event with source and destination",
			eventName: "rename",
			eventData: map[string]interface{}{
				"source":               map[string]interface{}{"path": "/Users/test/old.txt", "path_truncated": false},
				"destination_new_path": map[string]interface{}{"path": "/Users/test/new.txt", "path_truncated": false},
			},
			expectPaths: []string{"/Users/test/old.txt", "/Users/test/new.txt"},
			expectClass: opWrite,
		},
		{
			name:      "truncated path is skipped",
			eventName: "open",
			eventData: map[string]interface{}{
				"file":  map[string]interface{}{"path": "/Users/test/very/long/path", "path_truncated": true},
				"fflag": 0x0001,
			},
			expectPaths: nil,
			expectClass: opSkip,
		},
		{
			name:      "empty path is skipped",
			eventName: "write",
			eventData: map[string]interface{}{
				"target": map[string]interface{}{"path": "", "path_truncated": false},
			},
			expectPaths: nil,
			expectClass: opSkip,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventJSON, _ := json.Marshal(tt.eventData)
			ev := &esloggerEvent{
				EventType: 0,
				Event: map[string]json.RawMessage{
					tt.eventName: json.RawMessage(eventJSON),
				},
			}

			paths, class := classifyEsloggerEvent(ev, tt.eventName)
			if class != tt.expectClass {
				t.Errorf("class = %d, want %d", class, tt.expectClass)
			}
			if tt.expectPaths == nil {
				if len(paths) != 0 {
					t.Errorf("paths = %v, want nil", paths)
				}
			} else {
				if len(paths) != len(tt.expectPaths) {
					t.Errorf("paths = %v, want %v", paths, tt.expectPaths)
				} else {
					for i, p := range paths {
						if p != tt.expectPaths[i] {
							t.Errorf("paths[%d] = %q, want %q", i, p, tt.expectPaths[i])
						}
					}
				}
			}
		})
	}
}

func TestParseEsloggerLog(t *testing.T) {
	home, _ := os.UserHomeDir()

	// Root PID is 100; it forks child PID 101, which forks grandchild 102.
	// PID 200 is an unrelated process.
	lines := []string{
		// Fork: root (100) -> child (101)
		makeEsloggerLine("fork", 11, 100, map[string]interface{}{
			"child": map[string]interface{}{
				"audit_token": map[string]interface{}{"pid": 101},
				"executable":  map[string]interface{}{"path": "/usr/bin/child", "path_truncated": false},
				"ppid":        100,
			},
		}),
		// Fork: child (101) -> grandchild (102)
		makeEsloggerLine("fork", 11, 101, map[string]interface{}{
			"child": map[string]interface{}{
				"audit_token": map[string]interface{}{"pid": 102},
				"executable":  map[string]interface{}{"path": "/usr/bin/grandchild", "path_truncated": false},
				"ppid":        101,
			},
		}),
		// Write by root process (should be included) — write uses "target"
		makeEsloggerLine("write", 33, 100, map[string]interface{}{
			"target": map[string]interface{}{"path": filepath.Join(home, ".cache/testapp/db.sqlite"), "path_truncated": false},
		}),
		// Create by child (should be included) — create uses destination.existing_file
		makeEsloggerLine("create", 13, 101, map[string]interface{}{
			"destination_type": 0,
			"destination": map[string]interface{}{
				"existing_file": map[string]interface{}{"path": filepath.Join(home, ".config/testapp/conf.json"), "path_truncated": false},
			},
		}),
		// Open (read-only) by grandchild (should be included as read)
		makeEsloggerLine("open", 10, 102, map[string]interface{}{
			"file":  map[string]interface{}{"path": filepath.Join(home, ".config/testapp/extra.json"), "path_truncated": false},
			"fflag": 0x0001,
		}),
		// Open (write) by grandchild (should be included as write)
		makeEsloggerLine("open", 10, 102, map[string]interface{}{
			"file":  map[string]interface{}{"path": filepath.Join(home, ".cache/testapp/version"), "path_truncated": false},
			"fflag": 0x0003,
		}),
		// Write by unrelated PID 200 (should NOT be included)
		makeEsloggerLine("write", 33, 200, map[string]interface{}{
			"target": map[string]interface{}{"path": filepath.Join(home, ".cache/otherapp/data"), "path_truncated": false},
		}),
		// System path write by root PID (should be filtered)
		makeEsloggerLine("write", 33, 100, map[string]interface{}{
			"target": map[string]interface{}{"path": "/dev/null", "path_truncated": false},
		}),
		// Unlink by child (should be included) — unlink uses "target"
		makeEsloggerLine("unlink", 32, 101, map[string]interface{}{
			"target": map[string]interface{}{"path": filepath.Join(home, ".cache/testapp/old.tmp"), "path_truncated": false},
		}),
	}

	logContent := strings.Join(lines, "\n")
	logFile := filepath.Join(t.TempDir(), "eslogger.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ParseEsloggerLog(logFile, 100, false)
	if err != nil {
		t.Fatalf("ParseEsloggerLog() error: %v", err)
	}

	// Check write paths
	expectedWrites := map[string]bool{
		filepath.Join(home, ".cache/testapp/db.sqlite"):  false,
		filepath.Join(home, ".config/testapp/conf.json"): false,
		filepath.Join(home, ".cache/testapp/version"):    false,
		filepath.Join(home, ".cache/testapp/old.tmp"):    false,
	}
	for _, p := range result.WritePaths {
		if _, ok := expectedWrites[p]; ok {
			expectedWrites[p] = true
		}
	}
	for p, found := range expectedWrites {
		if !found {
			t.Errorf("WritePaths missing expected: %q, got: %v", p, result.WritePaths)
		}
	}

	// Check that unrelated PID 200 paths were not included
	for _, p := range result.WritePaths {
		if strings.Contains(p, "otherapp") {
			t.Errorf("WritePaths should not contain otherapp path: %q", p)
		}
	}

	// Check read paths
	expectedReads := map[string]bool{
		filepath.Join(home, ".config/testapp/extra.json"): false,
	}
	for _, p := range result.ReadPaths {
		if _, ok := expectedReads[p]; ok {
			expectedReads[p] = true
		}
	}
	for p, found := range expectedReads {
		if !found {
			t.Errorf("ReadPaths missing expected: %q, got: %v", p, result.ReadPaths)
		}
	}
}

func TestParseEsloggerLogForkChaining(t *testing.T) {
	home, _ := os.UserHomeDir()

	// Test deep fork chains: 100 -> 101 -> 102 -> 103
	lines := []string{
		makeEsloggerLine("fork", 11, 100, map[string]interface{}{
			"child": map[string]interface{}{
				"audit_token": map[string]interface{}{"pid": 101},
				"executable":  map[string]interface{}{"path": "/bin/sh", "path_truncated": false},
				"ppid":        100,
			},
		}),
		makeEsloggerLine("fork", 11, 101, map[string]interface{}{
			"child": map[string]interface{}{
				"audit_token": map[string]interface{}{"pid": 102},
				"executable":  map[string]interface{}{"path": "/usr/bin/node", "path_truncated": false},
				"ppid":        101,
			},
		}),
		makeEsloggerLine("fork", 11, 102, map[string]interface{}{
			"child": map[string]interface{}{
				"audit_token": map[string]interface{}{"pid": 103},
				"executable":  map[string]interface{}{"path": "/usr/bin/ruby", "path_truncated": false},
				"ppid":        102,
			},
		}),
		// Write from the deepest child
		makeEsloggerLine("write", 33, 103, map[string]interface{}{
			"target": map[string]interface{}{"path": filepath.Join(home, ".cache/app/deep.log"), "path_truncated": false},
		}),
	}

	logContent := strings.Join(lines, "\n")
	logFile := filepath.Join(t.TempDir(), "eslogger.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ParseEsloggerLog(logFile, 100, false)
	if err != nil {
		t.Fatalf("ParseEsloggerLog() error: %v", err)
	}

	// The deep child's write should be included
	found := false
	for _, p := range result.WritePaths {
		if strings.Contains(p, "deep.log") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("WritePaths should include deep child write, got: %v", result.WritePaths)
	}
}

func TestShouldFilterPathMacOS(t *testing.T) {
	home := "/Users/testuser"
	tests := []struct {
		path     string
		expected bool
	}{
		{"/dev/null", true},
		{"/private/var/run/syslog", true},
		{"/private/var/db/something", true},
		{"/private/var/folders/xx/yy", true},
		{"/System/Library/Frameworks/foo", true},
		{"/Library/Preferences/com.apple.foo", true},
		{"/usr/lib/libSystem.B.dylib", true},
		{"/usr/share/zoneinfo/UTC", true},
		{"/private/etc/hosts", true},
		{"/tmp/somefile", true},
		{"/private/tmp/somefile", true},
		{"/usr/local/lib/libfoo.dylib", true}, // .dylib
		{"/other/user/file", true},            // outside home
		{"/Users/testuser", true},             // exact home match
		{"", true},                            // empty
		{"relative/path", true},               // relative
		{"/Users/testuser/.cache/app/db", false},
		{"/Users/testuser/project/main.go", false},
		{"/Users/testuser/.config/app/conf.json", false},
		{"/tmp/greywall-eslogger-abc.log", true},                        // greywall infrastructure
		{"/Users/testuser/.antigen/bundles/rupa/z/zig", true},           // shell infra
		{"/Users/testuser/.oh-my-zsh/plugins/git/git.plugin.zsh", true}, // shell infra
		{"/Users/testuser/.pyenv/shims/ruby", true},                     // shell infra
		{"/Users/testuser/.bun/bin/node", true},                         // shell infra
		{"/Users/testuser/.local/bin/rg", true},                         // shell infra
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := shouldFilterPathMacOS(tt.path, home)
			if got != tt.expected {
				t.Errorf("shouldFilterPathMacOS(%q, %q) = %v, want %v", tt.path, home, got, tt.expected)
			}
		})
	}
}

func TestCheckLearningAvailable(t *testing.T) {
	err := CheckLearningAvailable()
	if err != nil {
		t.Logf("learning not available (expected if eslogger missing): %v", err)
	}
}

func TestParseEsloggerLogEmpty(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "empty.log")
	if err := os.WriteFile(logFile, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ParseEsloggerLog(logFile, 100, false)
	if err != nil {
		t.Fatalf("ParseEsloggerLog() error: %v", err)
	}

	if len(result.WritePaths) != 0 {
		t.Errorf("expected 0 write paths, got %d", len(result.WritePaths))
	}
	if len(result.ReadPaths) != 0 {
		t.Errorf("expected 0 read paths, got %d", len(result.ReadPaths))
	}
}

func TestParseEsloggerLogMalformedJSON(t *testing.T) {
	lines := []string{
		"not valid json at all",
		"{partial json",
		makeEsloggerLine("write", 33, 100, map[string]interface{}{
			"target": map[string]interface{}{"path": "/Users/test/.cache/app/good.txt", "path_truncated": false},
		}),
	}

	logContent := strings.Join(lines, "\n")
	logFile := filepath.Join(t.TempDir(), "malformed.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Should not error — malformed lines are skipped
	result, err := ParseEsloggerLog(logFile, 100, false)
	if err != nil {
		t.Fatalf("ParseEsloggerLog() error: %v", err)
	}
	_ = result
}

func TestScanForkEvents(t *testing.T) {
	lines := []string{
		makeEsloggerLine("fork", 11, 100, map[string]interface{}{
			"child": map[string]interface{}{
				"audit_token": map[string]interface{}{"pid": 101},
				"executable":  map[string]interface{}{"path": "/bin/sh", "path_truncated": false},
				"ppid":        100,
			},
		}),
		makeEsloggerLine("write", 33, 100, map[string]interface{}{
			"target": map[string]interface{}{"path": "/Users/test/file.txt", "path_truncated": false},
		}),
		makeEsloggerLine("fork", 11, 101, map[string]interface{}{
			"child": map[string]interface{}{
				"audit_token": map[string]interface{}{"pid": 102},
				"executable":  map[string]interface{}{"path": "/usr/bin/node", "path_truncated": false},
				"ppid":        101,
			},
		}),
	}

	logContent := strings.Join(lines, "\n")
	logFile := filepath.Join(t.TempDir(), "forks.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0o600); err != nil {
		t.Fatal(err)
	}

	forks, err := scanForkEvents(logFile)
	if err != nil {
		t.Fatalf("scanForkEvents() error: %v", err)
	}

	if len(forks) != 2 {
		t.Fatalf("expected 2 fork records, got %d", len(forks))
	}

	expected := []forkRecord{
		{parentPID: 100, childPID: 101},
		{parentPID: 101, childPID: 102},
	}
	for i, f := range forks {
		if f.parentPID != expected[i].parentPID || f.childPID != expected[i].childPID {
			t.Errorf("fork[%d] = {parent:%d, child:%d}, want {parent:%d, child:%d}",
				i, f.parentPID, f.childPID, expected[i].parentPID, expected[i].childPID)
		}
	}
}

func TestFwriteFlag(t *testing.T) {
	if fwriteFlag != 0x0002 {
		t.Errorf("fwriteFlag = 0x%04x, want 0x0002", fwriteFlag)
	}

	tests := []struct {
		name    string
		fflag   int
		isWrite bool
	}{
		{"FREAD only", 0x0001, false},
		{"FWRITE only", 0x0002, true},
		{"FREAD|FWRITE", 0x0003, true},
		{"FREAD|FWRITE|O_CREAT", 0x0203, true},
		{"zero", 0x0000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fflag&fwriteFlag != 0
			if got != tt.isWrite {
				t.Errorf("fflag 0x%04x & FWRITE = %v, want %v", tt.fflag, got, tt.isWrite)
			}
		})
	}
}

func TestParseEsloggerLogLink(t *testing.T) {
	home, _ := os.UserHomeDir()

	lines := []string{
		makeEsloggerLine("link", 42, 100, map[string]interface{}{
			"source":     map[string]interface{}{"path": filepath.Join(home, ".cache/app/source.txt"), "path_truncated": false},
			"target_dir": map[string]interface{}{"path": filepath.Join(home, ".cache/app/links"), "path_truncated": false},
		}),
	}

	logContent := strings.Join(lines, "\n")
	logFile := filepath.Join(t.TempDir(), "link.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ParseEsloggerLog(logFile, 100, false)
	if err != nil {
		t.Fatalf("ParseEsloggerLog() error: %v", err)
	}

	expectedWrites := map[string]bool{
		filepath.Join(home, ".cache/app/source.txt"): false,
		filepath.Join(home, ".cache/app/links"):      false,
	}
	for _, p := range result.WritePaths {
		if _, ok := expectedWrites[p]; ok {
			expectedWrites[p] = true
		}
	}
	for p, found := range expectedWrites {
		if !found {
			t.Errorf("WritePaths missing expected: %q, got: %v", p, result.WritePaths)
		}
	}
}

func TestParseEsloggerLogDebugOutput(t *testing.T) {
	home, _ := os.UserHomeDir()

	lines := []string{
		makeEsloggerLine("write", 33, 100, map[string]interface{}{
			"target": map[string]interface{}{"path": filepath.Join(home, ".cache/app/test.txt"), "path_truncated": false},
		}),
	}

	logContent := strings.Join(lines, "\n")
	logFile := filepath.Join(t.TempDir(), "debug.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Just verify debug=true doesn't panic
	_, err := ParseEsloggerLog(logFile, 100, true)
	if err != nil {
		t.Fatalf("ParseEsloggerLog() with debug=true error: %v", err)
	}
}
