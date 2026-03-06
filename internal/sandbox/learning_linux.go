//go:build linux

package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// straceSyscallRegex matches strace output lines for file-access syscalls.
var straceSyscallRegex = regexp.MustCompile(
	`(openat|mkdirat|unlinkat|renameat2|creat|symlinkat|linkat)\(`,
)

// openatWriteFlags matches O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND flags in strace output.
var openatWriteFlags = regexp.MustCompile(`O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)`)

// CheckLearningAvailable verifies that strace is installed and accessible.
func CheckLearningAvailable() error {
	_, err := exec.LookPath("strace")
	if err != nil {
		return fmt.Errorf("strace is required for learning mode but not found: %w\n\nInstall it with: sudo apt install strace (Debian/Ubuntu) or sudo pacman -S strace (Arch)", err)
	}
	return nil
}

// ParseStraceLog reads an strace output file and extracts unique read and write paths.
func ParseStraceLog(logPath string, debug bool) (*TraceResult, error) {
	f, err := os.Open(logPath) //nolint:gosec // user-controlled path from temp file - intentional
	if err != nil {
		return nil, fmt.Errorf("failed to open strace log: %w", err)
	}
	defer func() { _ = f.Close() }()

	home, _ := os.UserHomeDir()
	seenWrite := make(map[string]bool)
	seenRead := make(map[string]bool)
	result := &TraceResult{}

	scanner := bufio.NewScanner(f)
	// Increase buffer for long strace lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineCount := 0
	writeCount := 0
	readCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// Try extracting as a write path first
		writePath := extractWritePath(line)
		if writePath != "" {
			writeCount++
			if !shouldFilterPath(writePath, home) && !seenWrite[writePath] {
				seenWrite[writePath] = true
				result.WritePaths = append(result.WritePaths, writePath)
			}
			continue
		}

		// Try extracting as a read path
		readPath := extractReadPath(line)
		if readPath != "" {
			readCount++
			if !shouldFilterPath(readPath, home) && !seenRead[readPath] {
				seenRead[readPath] = true
				result.ReadPaths = append(result.ReadPaths, readPath)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading strace log: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Parsed strace log: %d lines, %d write syscalls, %d read syscalls, %d unique write paths, %d unique read paths\n",
			lineCount, writeCount, readCount, len(result.WritePaths), len(result.ReadPaths))
	}

	return result, nil
}

// extractReadPath parses a single strace line and returns the read path, if any.
// Only matches openat() with O_RDONLY (no write flags).
func extractReadPath(line string) string {
	if !strings.Contains(line, "openat(") {
		return ""
	}

	// Skip failed syscalls
	if strings.Contains(line, "= -1 ") {
		return ""
	}

	// Skip resumed/unfinished lines
	if strings.Contains(line, "<unfinished") || strings.Contains(line, "resumed>") {
		return ""
	}

	// Only care about read-only opens (no write flags)
	if openatWriteFlags.MatchString(line) {
		return ""
	}

	// Skip directory opens (O_DIRECTORY) — these are just directory traversal
	// (readdir/stat), not meaningful file reads
	if strings.Contains(line, "O_DIRECTORY") {
		return ""
	}

	return extractATPath(line)
}

// extractWritePath parses a single strace line and returns the write target path, if any.
func extractWritePath(line string) string {
	// Skip lines that don't contain write syscalls
	if !straceSyscallRegex.MatchString(line) {
		return ""
	}

	// Skip failed syscalls (lines ending with = -1 ENOENT or similar errors)
	if strings.Contains(line, "= -1 ") {
		return ""
	}

	// Skip resumed/unfinished lines
	if strings.Contains(line, "<unfinished") || strings.Contains(line, "resumed>") {
		return ""
	}

	// Extract path based on syscall type
	if strings.Contains(line, "openat(") {
		return extractOpenatPath(line)
	}
	if strings.Contains(line, "mkdirat(") {
		return extractATPath(line)
	}
	if strings.Contains(line, "unlinkat(") {
		return extractATPath(line)
	}
	if strings.Contains(line, "renameat2(") {
		return extractRenameatPath(line)
	}
	if strings.Contains(line, "creat(") {
		return extractCreatPath(line)
	}
	if strings.Contains(line, "symlinkat(") {
		return extractSymlinkTarget(line)
	}
	if strings.Contains(line, "linkat(") {
		return extractLinkatTarget(line)
	}

	return ""
}

// extractOpenatPath extracts the path from an openat() line, only if write flags are present.
func extractOpenatPath(line string) string {
	// Only care about writes
	if !openatWriteFlags.MatchString(line) {
		return ""
	}
	return extractATPath(line)
}

// extractATPath extracts the second argument (path) from AT_FDCWD-based syscalls.
// Pattern: syscall(AT_FDCWD, "/path/to/file", ...)
func extractATPath(line string) string {
	// Find the first quoted string after AT_FDCWD
	idx := strings.Index(line, "AT_FDCWD, \"")
	if idx < 0 {
		return ""
	}
	start := idx + len("AT_FDCWD, \"")
	end := strings.Index(line[start:], "\"")
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

// extractCreatPath extracts the path from a creat() call.
// Pattern: creat("/path/to/file", mode)
func extractCreatPath(line string) string {
	idx := strings.Index(line, "creat(\"")
	if idx < 0 {
		return ""
	}
	start := idx + len("creat(\"")
	end := strings.Index(line[start:], "\"")
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

// extractRenameatPath extracts the destination path from renameat2().
// Pattern: renameat2(AT_FDCWD, "/old", AT_FDCWD, "/new", flags)
// We want both old and new paths, but primarily the new (destination) path.
func extractRenameatPath(line string) string {
	// Find the second AT_FDCWD occurrence for the destination
	first := strings.Index(line, "AT_FDCWD, \"")
	if first < 0 {
		return ""
	}
	rest := line[first+len("AT_FDCWD, \""):]
	endFirst := strings.Index(rest, "\"")
	if endFirst < 0 {
		return ""
	}
	rest = rest[endFirst+1:]

	// Find second AT_FDCWD
	second := strings.Index(rest, "AT_FDCWD, \"")
	if second < 0 {
		// Fall back to first path
		return extractATPath(line)
	}
	start := second + len("AT_FDCWD, \"")
	end := strings.Index(rest[start:], "\"")
	if end < 0 {
		return extractATPath(line)
	}
	return rest[start : start+end]
}

// extractSymlinkTarget extracts the link path (destination) from symlinkat().
// Pattern: symlinkat("/target", AT_FDCWD, "/link")
func extractSymlinkTarget(line string) string {
	// The link path is the third argument (after AT_FDCWD)
	return extractATPath(line)
}

// extractLinkatTarget extracts the new link path from linkat().
// Pattern: linkat(AT_FDCWD, "/old", AT_FDCWD, "/new", flags)
func extractLinkatTarget(line string) string {
	return extractRenameatPath(line)
}

// shouldFilterPath returns true if a path should be excluded from learning results.
func shouldFilterPath(path, home string) bool {
	// Filter empty or relative paths
	if path == "" || !strings.HasPrefix(path, "/") {
		return true
	}

	// Filter system paths
	systemPrefixes := []string{
		"/proc/",
		"/sys/",
		"/dev/",
		"/run/",
		"/var/run/",
		"/var/lock/",
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Filter /tmp (sandbox has its own tmpfs)
	if strings.HasPrefix(path, "/tmp/") || path == "/tmp" {
		return true
	}

	// Filter shared object files (.so, .so.*)
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.") {
		return true
	}

	// Filter greywall infrastructure files
	if strings.Contains(path, "greywall-") {
		return true
	}

	// Filter paths outside home (they're typically system-level)
	if home != "" && !strings.HasPrefix(path, home+"/") {
		return true
	}

	return false
}
