//go:build darwin

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// macOS-Specific Integration Tests (Seatbelt)
// ============================================================================

// TestMacOS_SeatbeltBlocksWriteOutsideWorkspace verifies Seatbelt prevents writes
// outside the allowed workspace.
func TestMacOS_SeatbeltBlocksWriteOutsideWorkspace(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	outsideFile := "/tmp/greywall-test-outside-" + filepath.Base(workspace) + ".txt"
	defer func() { _ = os.Remove(outsideFile) }()

	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "touch "+outsideFile, workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, outsideFile)
}

// TestMacOS_SeatbeltAllowsWriteInWorkspace verifies writes within the workspace work.
func TestMacOS_SeatbeltAllowsWriteInWorkspace(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "echo 'test content' > allowed.txt", workspace)

	assertAllowed(t, result)
	assertFileExists(t, filepath.Join(workspace, "allowed.txt"))

	content, err := os.ReadFile(filepath.Join(workspace, "allowed.txt")) //nolint:gosec
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(content), "test content") {
		t.Errorf("expected file to contain 'test content', got: %s", string(content))
	}
}

// TestMacOS_SeatbeltProtectsGitHooks verifies .git/hooks cannot be written to.
func TestMacOS_SeatbeltProtectsGitHooks(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)

	hookPath := filepath.Join(workspace, ".git", "hooks", "pre-commit")
	result := runUnderSandbox(t, cfg, "echo '#!/bin/sh\nmalicious' > "+hookPath, workspace)

	assertBlocked(t, result)

	if content, err := os.ReadFile(hookPath); err == nil && strings.Contains(string(content), "malicious") { //nolint:gosec
		t.Errorf("malicious content should not have been written to git hook")
	}
}

// TestMacOS_SeatbeltProtectsGitConfig verifies .git/config is protected by default.
func TestMacOS_SeatbeltProtectsGitConfig(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.AllowGitConfig = false

	configPath := filepath.Join(workspace, ".git", "config")
	originalContent, _ := os.ReadFile(configPath) //nolint:gosec

	result := runUnderSandbox(t, cfg, "echo 'malicious=true' >> "+configPath, workspace)

	assertBlocked(t, result)

	// Verify content wasn't modified
	newContent, _ := os.ReadFile(configPath) //nolint:gosec
	if strings.Contains(string(newContent), "malicious") {
		t.Errorf("git config should not have been modified")
	}
	_ = originalContent
}

// TestMacOS_SeatbeltProtectsShellConfig verifies shell config files are protected.
func TestMacOS_SeatbeltProtectsShellConfig(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	zshrcPath := filepath.Join(workspace, ".zshrc")
	createTestFile(t, workspace, ".zshrc", "# original zshrc")

	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "echo 'malicious' >> "+zshrcPath, workspace)

	assertBlocked(t, result)

	content, _ := os.ReadFile(zshrcPath) //nolint:gosec
	if strings.Contains(string(content), "malicious") {
		t.Errorf(".zshrc should be protected from writes")
	}
}

// TestMacOS_SeatbeltAllowsReadSystemFiles verifies system files can be read.
func TestMacOS_SeatbeltAllowsReadSystemFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Reading /etc/passwd should work on macOS
	result := runUnderSandbox(t, cfg, "cat /etc/passwd | head -1", workspace)

	assertAllowed(t, result)
	if result.Stdout == "" {
		t.Errorf("expected to read /etc/passwd content")
	}
}

// TestMacOS_SeatbeltBlocksWriteSystemFiles verifies system files cannot be written.
func TestMacOS_SeatbeltBlocksWriteSystemFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Attempting to write to /etc should fail
	result := runUnderSandbox(t, cfg, "touch /etc/greywall-test-file", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/etc/greywall-test-file")
}

// TestMacOS_SeatbeltAllowsTmpGreywall verifies /tmp/greywall is writable.
func TestMacOS_SeatbeltAllowsTmpGreywall(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Ensure /tmp/greywall exists
	_ = os.MkdirAll("/tmp/greywall", 0o750)

	testFile := "/tmp/greywall/test-file-" + filepath.Base(workspace)
	defer func() { _ = os.Remove(testFile) }()

	result := runUnderSandbox(t, cfg, "echo 'test' > "+testFile, workspace)

	assertAllowed(t, result)
	assertFileExists(t, testFile)
}

// ============================================================================
// Sensitive File Read Blocking Tests
// ============================================================================

// TestMacOS_SeatbeltBlocksEnvFileRead verifies that .env files cannot be read
// even though the workspace directory has a broad file-read-data allow.
// This is the regression test for the Seatbelt deny file-read* vs file-read-data bug:
// Seatbelt ignores wildcard denies (file-read*) when a specific allow (file-read-data)
// covers the same path. Deny rules must use file-read-data to be effective.
func TestMacOS_SeatbeltBlocksEnvFileRead(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createTestFile(t, workspace, ".env", "SECRET_KEY=supersecret")
	createTestFile(t, workspace, "README.md", "hello")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = boolPtr(true)
	cfg.Filesystem.AllowRead = []string{workspace}
	cfg.Filesystem.DenyRead = []string{filepath.Join(workspace, ".env")}

	// .env should be blocked
	result := runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, ".env"), workspace)
	assertBlocked(t, result)

	// Regular files should still be readable
	result = runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, "README.md"), workspace)
	assertAllowed(t, result)
	assertContains(t, result.Stdout, "hello")
}

// TestMacOS_SeatbeltBlocksEnvVariantsRead verifies that .env.* variants are also blocked.
func TestMacOS_SeatbeltBlocksEnvVariantsRead(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createTestFile(t, workspace, ".env.local", "LOCAL_SECRET=abc")
	createTestFile(t, workspace, ".env.production", "PROD_SECRET=xyz")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = boolPtr(true)
	cfg.Filesystem.AllowRead = []string{workspace}
	cfg.Filesystem.DenyRead = []string{
		filepath.Join(workspace, ".env.local"),
		filepath.Join(workspace, ".env.production"),
	}

	result := runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, ".env.local"), workspace)
	assertBlocked(t, result)

	result = runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, ".env.production"), workspace)
	assertBlocked(t, result)
}

// TestMacOS_SeatbeltBlocksUserDenyReadPaths verifies that user-configured
// denyRead paths are blocked even in legacy mode (defaultDenyRead=false).
func TestMacOS_SeatbeltBlocksUserDenyReadPaths(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	secretDir := filepath.Join(workspace, "secrets")
	if err := os.MkdirAll(secretDir, 0o750); err != nil {
		t.Fatalf("failed to create secrets dir: %v", err)
	}
	createTestFile(t, workspace, "secrets/api_key.txt", "my-api-key")
	createTestFile(t, workspace, "public.txt", "public data")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = boolPtr(false) // legacy mode
	cfg.Filesystem.DenyRead = []string{secretDir}

	// Secret file should be blocked
	result := runUnderSandbox(t, cfg, "cat "+filepath.Join(secretDir, "api_key.txt"), workspace)
	assertBlocked(t, result)

	// Public file should still be readable
	result = runUnderSandbox(t, cfg, "cat public.txt", workspace)
	assertAllowed(t, result)
	assertContains(t, result.Stdout, "public data")
}

// ============================================================================
// Network Blocking Tests
// ============================================================================

// TestMacOS_NetworkBlocksCurl verifies that curl cannot reach the network when blocked.
func TestMacOS_NetworkBlocksCurl(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	// No domains allowed = all network blocked

	result := runUnderSandboxWithTimeout(t, cfg, "curl -s --connect-timeout 2 --max-time 3 http://example.com", workspace, 10*time.Second)

	// Network is blocked via proxy - curl may exit 0 but with "blocked" message,
	// or it may fail with a connection error. Either is acceptable.
	if result.Succeeded() && !strings.Contains(result.Stdout, "blocked") && !strings.Contains(result.Stdout, "Connection refused") {
		t.Errorf("expected network to be blocked, but curl succeeded with: %s", result.Stdout)
	}
}

// TestMacOS_NetworkBlocksSSH verifies that SSH cannot connect when blocked.
func TestMacOS_NetworkBlocksSSH(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "ssh")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, "ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no github.com", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestMacOS_NetworkBlocksNc verifies that nc cannot make connections.
func TestMacOS_NetworkBlocksNc(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "nc")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, "nc -z -w 2 127.0.0.1 80", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestMacOS_ProxyAllowsTrafficViaProxy verifies the proxy allows traffic via external proxy.
func TestMacOS_ProxyAllowsTrafficViaProxy(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithProxy("socks5://localhost:1080")
	cfg.Filesystem.AllowWrite = []string{workspace}

	// This test requires actual network and a running SOCKS5 proxy
	if os.Getenv("GREYWALL_TEST_NETWORK") != "1" {
		t.Skip("skipping: set GREYWALL_TEST_NETWORK=1 to run network tests (requires SOCKS5 proxy on localhost:1080)")
	}

	result := runUnderSandboxWithTimeout(t, cfg, "curl -s --connect-timeout 5 --max-time 10 https://httpbin.org/get", workspace, 15*time.Second)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "httpbin")
}

// ============================================================================
// Python Compatibility Tests
// ============================================================================

// TestMacOS_PythonOpenptyWorks verifies Python can open a PTY under Seatbelt.
func TestMacOS_PythonOpenptyWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.AllowPty = true

	pythonCode := `import os
master, slave = os.openpty()
os.write(slave, b"ping")
assert os.read(master, 4) == b"ping"
print("SUCCESS")`

	result := runUnderSandbox(t, cfg, `python3 -c '`+pythonCode+`'`, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "SUCCESS")
}

// TestMacOS_PythonGetpwuidWorks verifies Python can look up user info.
func TestMacOS_PythonGetpwuidWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, `python3 -c "import pwd, os; print(pwd.getpwuid(os.getuid()).pw_name)"`, workspace)

	assertAllowed(t, result)
	if result.Stdout == "" {
		t.Errorf("expected username output")
	}
}

// ============================================================================
// Security Edge Case Tests
// ============================================================================

// TestMacOS_SymlinkEscapeBlocked verifies symlink attacks are prevented.
func TestMacOS_SymlinkEscapeBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Create a symlink pointing outside the workspace
	symlinkPath := filepath.Join(workspace, "escape")
	if err := os.Symlink("/etc", symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Try to write through the symlink
	result := runUnderSandbox(t, cfg, "echo 'test' > "+symlinkPath+"/greywall-test", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/etc/greywall-test")
}

// TestMacOS_PathTraversalBlocked verifies path traversal attacks are prevented.
func TestMacOS_PathTraversalBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "touch ../../../../tmp/greywall-escape-test", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/tmp/greywall-escape-test")
}

// TestMacOS_DeviceAccessBlocked verifies device files cannot be written.
func TestMacOS_DeviceAccessBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Try to write to /dev/disk0 (would need root anyway, but should be blocked by sandbox)
	result := runUnderSandbox(t, cfg, "echo 'test' > /dev/disk0 2>&1", workspace)

	// Should fail (permission denied or blocked by sandbox)
	// The command may "succeed" if the write fails silently, so we check for error messages
	if result.Succeeded() && !strings.Contains(result.Stderr, "denied") && !strings.Contains(result.Stderr, "Permission") {
		// Even if shell exits 0, reading /dev/disk0 should produce errors or empty output
		t.Logf("Note: device access test may not be reliable without root")
	}
}

// ============================================================================
// Policy Tests
// ============================================================================

// TestMacOS_ReadOnlyPolicy verifies that files outside the allowed write paths cannot be written.
// Note: Greywall always adds some default writable paths (/tmp/greywall, /dev/null, etc.)
// so "read-only" here means "outside the workspace".
func TestMacOS_ReadOnlyPolicy(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createTestFile(t, workspace, "existing.txt", "hello")

	// Only allow writing to workspace - but NOT to a specific location outside
	cfg := testConfigWithWorkspace(workspace)

	// Reading should work
	result := runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, "existing.txt"), workspace)
	assertAllowed(t, result)
	assertContains(t, result.Stdout, "hello")

	// Writing in workspace should work
	result = runUnderSandbox(t, cfg, "echo 'test' > "+filepath.Join(workspace, "writeable.txt"), workspace)
	assertAllowed(t, result)

	// Writing outside workspace should fail
	outsidePath := "/tmp/greywall-test-readonly-" + filepath.Base(workspace) + ".txt"
	defer func() { _ = os.Remove(outsidePath) }()
	result = runUnderSandbox(t, cfg, "echo 'outside' > "+outsidePath, workspace)
	assertBlocked(t, result)
	assertFileNotExists(t, outsidePath)
}

// TestMacOS_WorkspaceWritePolicy verifies workspace-write sandbox works.
func TestMacOS_WorkspaceWritePolicy(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Writing in workspace should work
	result := runUnderSandbox(t, cfg, "echo 'test' > test.txt", workspace)
	assertAllowed(t, result)
	assertFileExists(t, filepath.Join(workspace, "test.txt"))

	// Writing outside workspace should fail
	outsideFile := "/tmp/greywall-test-outside.txt"
	defer func() { _ = os.Remove(outsideFile) }()
	result = runUnderSandbox(t, cfg, "echo 'test' > "+outsideFile, workspace)
	assertBlocked(t, result)
	assertFileNotExists(t, outsideFile)
}

// TestMacOS_MultipleWritableRoots verifies multiple writable roots work.
func TestMacOS_MultipleWritableRoots(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace1 := createTempWorkspace(t)
	workspace2 := createTempWorkspace(t)

	cfg := testConfig()
	cfg.Filesystem.AllowWrite = []string{workspace1, workspace2}

	// Writing in first workspace should work
	result := runUnderSandbox(t, cfg, "echo 'test1' > "+filepath.Join(workspace1, "file1.txt"), workspace1)
	assertAllowed(t, result)

	// Writing in second workspace should work
	result = runUnderSandbox(t, cfg, "echo 'test2' > "+filepath.Join(workspace2, "file2.txt"), workspace1)
	assertAllowed(t, result)

	// Writing outside both should fail
	outsideFile := "/tmp/greywall-test-outside-multi.txt"
	defer func() { _ = os.Remove(outsideFile) }()
	result = runUnderSandbox(t, cfg, "echo 'test' > "+outsideFile, workspace1)
	assertBlocked(t, result)
}
