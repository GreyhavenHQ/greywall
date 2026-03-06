//go:build darwin

package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// opClass classifies a filesystem operation.
type opClass int

const (
	opSkip opClass = iota
	opRead
	opWrite
)

// fwriteFlag is the macOS FWRITE flag value (O_WRONLY or O_RDWR includes this).
const fwriteFlag = 0x0002

// eslogger JSON types — mirrors the real Endpoint Security framework output.
// eslogger emits one JSON object per line to stdout.
//
// Key structural details from real eslogger output:
// - event_type is an integer (e.g., 10=open, 11=fork, 13=create, 32=unlink, 33=write, 41=truncate)
// - Event data is nested under event.{event_name} (e.g., event.open, event.fork)
// - write/unlink/truncate use "target" not "file"
// - create uses destination.existing_file
// - fork child has full process info including audit_token

// esloggerEvent is the top-level event from eslogger.
type esloggerEvent struct {
	EventType int                        `json:"event_type"`
	Process   esloggerProcess            `json:"process"`
	Event     map[string]json.RawMessage `json:"event"`
}

type esloggerProcess struct {
	AuditToken esloggerAuditToken `json:"audit_token"`
	Executable esloggerExec       `json:"executable"`
	PPID       int                `json:"ppid"`
}

type esloggerAuditToken struct {
	PID int `json:"pid"`
}

type esloggerExec struct {
	Path          string `json:"path"`
	PathTruncated bool   `json:"path_truncated"`
}

// Event-specific types.

type esloggerOpenEvent struct {
	File  esloggerFile `json:"file"`
	Fflag int          `json:"fflag"`
}

type esloggerTargetEvent struct {
	Target esloggerFile `json:"target"`
}

type esloggerCreateEvent struct {
	DestinationType int                `json:"destination_type"`
	Destination     esloggerCreateDest `json:"destination"`
}

type esloggerCreateDest struct {
	ExistingFile *esloggerFile    `json:"existing_file,omitempty"`
	NewPath      *esloggerNewPath `json:"new_path,omitempty"`
}

type esloggerNewPath struct {
	Dir      esloggerFile `json:"dir"`
	Filename string       `json:"filename"`
}

type esloggerRenameEvent struct {
	Source      esloggerFile `json:"source"`
	Destination esloggerFile `json:"destination_new_path"`
}

type esloggerForkEvent struct {
	Child esloggerForkChild `json:"child"`
}

type esloggerForkChild struct {
	AuditToken esloggerAuditToken `json:"audit_token"`
	Executable esloggerExec       `json:"executable"`
	PPID       int                `json:"ppid"`
}

type esloggerLinkEvent struct {
	Source    esloggerFile `json:"source"`
	TargetDir esloggerFile `json:"target_dir"`
}

type esloggerFile struct {
	Path          string `json:"path"`
	PathTruncated bool   `json:"path_truncated"`
}

// CheckLearningAvailable verifies that eslogger exists on macOS.
func CheckLearningAvailable() error {
	if _, err := os.Stat("/usr/bin/eslogger"); err != nil {
		return fmt.Errorf("eslogger not found at /usr/bin/eslogger (requires macOS 13+): %w", err)
	}
	return nil
}

// eventName extracts the event name string from the event map.
// eslogger nests event data under event.{name}, e.g., event.open, event.fork.
func eventName(ev *esloggerEvent) string {
	for key := range ev.Event {
		return key
	}
	return ""
}

// ParseEsloggerLog reads an eslogger JSON log, builds the process tree from
// fork events starting at rootPID, then filters filesystem events by the PID set.
// Uses a two-pass approach: pass 1 scans fork events to build the PID tree,
// pass 2 filters filesystem events by the PID set.
func ParseEsloggerLog(logPath string, rootPID int, debug bool) (*TraceResult, error) {
	home, _ := os.UserHomeDir()
	seenWrite := make(map[string]bool)
	seenRead := make(map[string]bool)
	result := &TraceResult{}

	// Pass 1: Build the PID set from fork events.
	pidSet := map[int]bool{rootPID: true}
	forkEvents, err := scanForkEvents(logPath)
	if err != nil {
		return nil, err
	}

	// BFS: expand PID set using fork parent→child relationships.
	// We may need multiple rounds since a child can itself fork.
	changed := true
	for changed {
		changed = false
		for _, fe := range forkEvents {
			if pidSet[fe.parentPID] && !pidSet[fe.childPID] {
				pidSet[fe.childPID] = true
				changed = true
			}
		}
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] eslogger PID tree from root %d: %d PIDs\n", rootPID, len(pidSet))
	}

	// Pass 2: Scan filesystem events, filter by PID set.
	f, err := os.Open(logPath) //nolint:gosec // temp file path from learning session
	if err != nil {
		return nil, fmt.Errorf("failed to open eslogger log: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 4*1024*1024)

	lineCount := 0
	matchedLines := 0
	writeCount := 0
	readCount := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		lineCount++

		var ev esloggerEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}

		name := eventName(&ev)

		// Skip fork events (already processed in pass 1)
		if name == "fork" {
			continue
		}

		// Filter by PID set
		pid := ev.Process.AuditToken.PID
		if !pidSet[pid] {
			continue
		}
		matchedLines++

		// Extract path and classify operation
		paths, class := classifyEsloggerEvent(&ev, name)
		if class == opSkip || len(paths) == 0 {
			continue
		}

		for _, path := range paths {
			if shouldFilterPathMacOS(path, home) {
				continue
			}

			switch class {
			case opWrite:
				writeCount++
				if !seenWrite[path] {
					seenWrite[path] = true
					result.WritePaths = append(result.WritePaths, path)
				}
			case opRead:
				readCount++
				if !seenRead[path] {
					seenRead[path] = true
					result.ReadPaths = append(result.ReadPaths, path)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading eslogger log: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Parsed eslogger log: %d lines, %d matched PIDs, %d writes, %d reads, %d unique write paths, %d unique read paths\n",
			lineCount, matchedLines, writeCount, readCount, len(result.WritePaths), len(result.ReadPaths))
	}

	return result, nil
}

// forkRecord stores a parent→child PID relationship from a fork event.
type forkRecord struct {
	parentPID int
	childPID  int
}

// scanForkEvents reads the log and extracts all fork parent→child PID pairs.
func scanForkEvents(logPath string) ([]forkRecord, error) {
	f, err := os.Open(logPath) //nolint:gosec // temp file path from learning session
	if err != nil {
		return nil, fmt.Errorf("failed to open eslogger log: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 4*1024*1024)

	var forks []forkRecord
	for scanner.Scan() {
		line := scanner.Bytes()

		// Quick pre-check to avoid parsing non-fork lines.
		if !strings.Contains(string(line), `"fork"`) {
			continue
		}

		var ev esloggerEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}

		forkRaw, ok := ev.Event["fork"]
		if !ok {
			continue
		}

		var fe esloggerForkEvent
		if err := json.Unmarshal(forkRaw, &fe); err != nil {
			continue
		}

		forks = append(forks, forkRecord{
			parentPID: ev.Process.AuditToken.PID,
			childPID:  fe.Child.AuditToken.PID,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading eslogger log for fork events: %w", err)
	}

	return forks, nil
}

// classifyEsloggerEvent extracts paths and classifies the operation from an eslogger event.
func classifyEsloggerEvent(ev *esloggerEvent, name string) ([]string, opClass) {
	eventRaw, ok := ev.Event[name]
	if !ok {
		return nil, opSkip
	}

	switch name {
	case "open":
		var oe esloggerOpenEvent
		if err := json.Unmarshal(eventRaw, &oe); err != nil {
			return nil, opSkip
		}
		path := oe.File.Path
		if path == "" || oe.File.PathTruncated {
			return nil, opSkip
		}
		if oe.Fflag&fwriteFlag != 0 {
			return []string{path}, opWrite
		}
		return []string{path}, opRead

	case "create":
		var ce esloggerCreateEvent
		if err := json.Unmarshal(eventRaw, &ce); err != nil {
			return nil, opSkip
		}
		if ce.Destination.ExistingFile != nil {
			path := ce.Destination.ExistingFile.Path
			if path != "" && !ce.Destination.ExistingFile.PathTruncated {
				return []string{path}, opWrite
			}
		}
		if ce.Destination.NewPath != nil {
			dir := ce.Destination.NewPath.Dir.Path
			filename := ce.Destination.NewPath.Filename
			if dir != "" && filename != "" {
				return []string{dir + "/" + filename}, opWrite
			}
		}
		return nil, opSkip

	case "write", "unlink", "truncate":
		var te esloggerTargetEvent
		if err := json.Unmarshal(eventRaw, &te); err != nil {
			return nil, opSkip
		}
		path := te.Target.Path
		if path == "" || te.Target.PathTruncated {
			return nil, opSkip
		}
		return []string{path}, opWrite

	case "rename":
		var re esloggerRenameEvent
		if err := json.Unmarshal(eventRaw, &re); err != nil {
			return nil, opSkip
		}
		var paths []string
		if re.Source.Path != "" && !re.Source.PathTruncated {
			paths = append(paths, re.Source.Path)
		}
		if re.Destination.Path != "" && !re.Destination.PathTruncated {
			paths = append(paths, re.Destination.Path)
		}
		if len(paths) == 0 {
			return nil, opSkip
		}
		return paths, opWrite

	case "link":
		var le esloggerLinkEvent
		if err := json.Unmarshal(eventRaw, &le); err != nil {
			return nil, opSkip
		}
		var paths []string
		if le.Source.Path != "" && !le.Source.PathTruncated {
			paths = append(paths, le.Source.Path)
		}
		if le.TargetDir.Path != "" && !le.TargetDir.PathTruncated {
			paths = append(paths, le.TargetDir.Path)
		}
		if len(paths) == 0 {
			return nil, opSkip
		}
		return paths, opWrite

	default:
		return nil, opSkip
	}
}

// shouldFilterPathMacOS returns true if a path should be excluded from macOS learning results.
func shouldFilterPathMacOS(path, home string) bool {
	if path == "" || !strings.HasPrefix(path, "/") {
		return true
	}

	// macOS system path prefixes to filter
	systemPrefixes := []string{
		"/dev/",
		"/private/var/run/",
		"/private/var/db/",
		"/private/var/folders/",
		"/System/",
		"/Library/",
		"/usr/lib/",
		"/usr/share/",
		"/private/etc/",
		"/tmp/",
		"/private/tmp/",
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Filter .dylib files (macOS shared libraries)
	if strings.HasSuffix(path, ".dylib") {
		return true
	}

	// Filter greywall infrastructure files
	if strings.Contains(path, "greywall-") {
		return true
	}

	// Filter paths outside home directory
	if home != "" && !strings.HasPrefix(path, home+"/") {
		return true
	}

	// Filter exact home directory match
	if path == home {
		return true
	}

	// Filter shell infrastructure directories (PATH lookups, plugin dirs)
	if home != "" {
		shellInfraPrefixes := []string{
			home + "/.antigen/",
			home + "/.oh-my-zsh/",
			home + "/.pyenv/shims/",
			home + "/.bun/bin/",
			home + "/.local/bin/",
		}
		for _, prefix := range shellInfraPrefixes {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}

	return false
}
