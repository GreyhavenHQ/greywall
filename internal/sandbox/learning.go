package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// wellKnownParents are directories under $HOME where applications typically
// create their own subdirectory (e.g., ~/.cache/opencode, ~/.config/opencode).
var wellKnownParents = []string{
	".cache",
	".config",
	".local/share",
	".local/state",
	".local/lib",
	".data",
}

// LearnedTemplateDir returns the directory where learned templates are stored.
func LearnedTemplateDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "greywall", "learned")
	}
	return filepath.Join(configDir, "greywall", "learned")
}

// LearnedTemplatePath returns the path where a command's learned template is stored.
func LearnedTemplatePath(cmdName string) string {
	return filepath.Join(LearnedTemplateDir(), SanitizeTemplateName(cmdName)+".json")
}

// SanitizeTemplateName sanitizes a command name for use as a filename.
// Only allows alphanumeric, dash, underscore, and dot characters.
func SanitizeTemplateName(name string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	sanitized := re.ReplaceAllString(name, "_")
	// Collapse multiple underscores
	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}
	sanitized = strings.Trim(sanitized, "_.")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

// GenerateLearnedTemplate parses an strace log, collapses paths, and saves a template.
// Returns the path where the template was saved.
func GenerateLearnedTemplate(straceLogPath, cmdName string, debug bool) (string, error) {
	result, err := ParseStraceLog(straceLogPath, debug)
	if err != nil {
		return "", fmt.Errorf("failed to parse strace log: %w", err)
	}

	home, _ := os.UserHomeDir()

	// Filter write paths: remove default writable and sensitive paths
	var filteredWrites []string
	for _, p := range result.WritePaths {
		if isDefaultWritablePath(p) {
			continue
		}
		if isSensitivePath(p, home) {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall] Skipping sensitive path: %s\n", p)
			}
			continue
		}
		filteredWrites = append(filteredWrites, p)
	}

	// Collapse write paths into minimal directory set
	collapsed := CollapsePaths(filteredWrites)

	// Convert write paths to tilde-relative
	var allowWrite []string
	allowWrite = append(allowWrite, ".") // Always include cwd
	for _, p := range collapsed {
		allowWrite = append(allowWrite, toTildePath(p, home))
	}

	// Convert read paths to tilde-relative for display
	var readDisplay []string
	for _, p := range result.ReadPaths {
		readDisplay = append(readDisplay, toTildePath(p, home))
	}

	// Print all discovered paths
	fmt.Fprintf(os.Stderr, "\n")

	if len(readDisplay) > 0 {
		fmt.Fprintf(os.Stderr, "[greywall] Discovered read paths:\n")
		for _, p := range readDisplay {
			fmt.Fprintf(os.Stderr, "[greywall]   %s\n", p)
		}
	}

	if len(allowWrite) > 1 { // >1 because "." is always included
		fmt.Fprintf(os.Stderr, "[greywall] Discovered write paths (collapsed):\n")
		for _, p := range allowWrite {
			if p == "." {
				continue
			}
			fmt.Fprintf(os.Stderr, "[greywall]   %s\n", p)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[greywall] No additional write paths discovered.\n")
	}

	fmt.Fprintf(os.Stderr, "\n")

	// Build template
	template := buildTemplate(cmdName, allowWrite)

	// Save template
	templatePath := LearnedTemplatePath(cmdName)
	if err := os.MkdirAll(filepath.Dir(templatePath), 0o755); err != nil {
		return "", fmt.Errorf("failed to create template directory: %w", err)
	}

	if err := os.WriteFile(templatePath, []byte(template), 0o644); err != nil {
		return "", fmt.Errorf("failed to write template: %w", err)
	}

	// Display the template content
	fmt.Fprintf(os.Stderr, "[greywall] Generated template:\n")
	for _, line := range strings.Split(template, "\n") {
		if line != "" {
			fmt.Fprintf(os.Stderr, "[greywall]   %s\n", line)
		}
	}
	fmt.Fprintf(os.Stderr, "\n")

	return templatePath, nil
}

// CollapsePaths groups write paths into minimal directory set.
// Uses "application directory" detection for well-known parents.
func CollapsePaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}

	home, _ := os.UserHomeDir()

	// Group paths by application directory
	appDirPaths := make(map[string][]string) // appDir -> list of paths
	var standalone []string                  // paths that don't fit an app dir

	for _, p := range paths {
		appDir := findApplicationDirectory(p, home)
		if appDir != "" {
			appDirPaths[appDir] = append(appDirPaths[appDir], p)
		} else {
			standalone = append(standalone, p)
		}
	}

	var result []string

	// For each app dir group: if 2+ paths share it, use the app dir
	// If only 1 path, use its parent directory
	for appDir, groupPaths := range appDirPaths {
		if len(groupPaths) >= 2 {
			result = append(result, appDir)
		} else {
			result = append(result, filepath.Dir(groupPaths[0]))
		}
	}

	// For standalone paths, use their parent directory
	for _, p := range standalone {
		result = append(result, filepath.Dir(p))
	}

	// Sort and deduplicate (remove sub-paths of other paths)
	sort.Strings(result)
	result = deduplicateSubPaths(result)

	return result
}

// findApplicationDirectory finds the app-level directory for a path.
// For paths under well-known parents (e.g., ~/.cache/opencode/foo),
// returns the first directory below the well-known parent (e.g., ~/.cache/opencode).
func findApplicationDirectory(path, home string) string {
	if home == "" {
		return ""
	}

	for _, parent := range wellKnownParents {
		prefix := filepath.Join(home, parent) + "/"
		if strings.HasPrefix(path, prefix) {
			// Get the first directory below the well-known parent
			rest := strings.TrimPrefix(path, prefix)
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) > 0 && parts[0] != "" {
				return filepath.Join(home, parent, parts[0])
			}
		}
	}

	return ""
}

// isDefaultWritablePath checks if a path is already writable by default in the sandbox.
func isDefaultWritablePath(path string) bool {
	// /tmp is always writable (tmpfs in sandbox)
	if strings.HasPrefix(path, "/tmp/") || path == "/tmp" {
		return false // /tmp inside sandbox is tmpfs, not host /tmp
	}

	for _, p := range GetDefaultWritePaths() {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}

	return false
}

// isSensitivePath checks if a path is sensitive and should not be made writable.
func isSensitivePath(path, home string) bool {
	if home == "" {
		return false
	}

	// Check against DangerousFiles
	for _, f := range DangerousFiles {
		dangerous := filepath.Join(home, f)
		if path == dangerous {
			return true
		}
	}

	// Check for .env files
	base := filepath.Base(path)
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}

	// Check SSH keys
	sshDir := filepath.Join(home, ".ssh")
	if strings.HasPrefix(path, sshDir+"/") {
		return true
	}

	// Check GPG
	gnupgDir := filepath.Join(home, ".gnupg")
	if strings.HasPrefix(path, gnupgDir+"/") {
		return true
	}

	return false
}

// getDangerousFilePatterns returns denyWrite entries for DangerousFiles.
func getDangerousFilePatterns() []string {
	var patterns []string
	for _, f := range DangerousFiles {
		patterns = append(patterns, "~/"+f)
	}
	return patterns
}

// getSensitiveReadPatterns returns denyRead entries for sensitive data.
func getSensitiveReadPatterns() []string {
	return []string{
		"~/.ssh/id_*",
		"~/.gnupg/**",
	}
}

// toTildePath converts an absolute path to a tilde-relative path if under home.
func toTildePath(p, home string) string {
	if home != "" && strings.HasPrefix(p, home+"/") {
		return "~/" + strings.TrimPrefix(p, home+"/")
	}
	return p
}

// LearnedTemplateInfo holds metadata about a learned template.
type LearnedTemplateInfo struct {
	Name string // template name (without .json)
	Path string // full path to the template file
}

// ListLearnedTemplates returns all available learned templates.
func ListLearnedTemplates() ([]LearnedTemplateInfo, error) {
	dir := LearnedTemplateDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var templates []LearnedTemplateInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		templates = append(templates, LearnedTemplateInfo{
			Name: name,
			Path: filepath.Join(dir, e.Name()),
		})
	}
	return templates, nil
}

// deduplicateSubPaths removes paths that are sub-paths of other paths in the list.
// Assumes the input is sorted.
func deduplicateSubPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}

	var result []string
	for i, p := range paths {
		isSubPath := false
		for j, other := range paths {
			if i == j {
				continue
			}
			if strings.HasPrefix(p, other+"/") {
				isSubPath = true
				break
			}
		}
		if !isSubPath {
			result = append(result, p)
		}
	}

	return result
}

// buildTemplate generates the JSONC template content for a learned config.
func buildTemplate(cmdName string, allowWrite []string) string {
	type fsConfig struct {
		AllowWrite []string `json:"allowWrite"`
		DenyWrite  []string `json:"denyWrite"`
		DenyRead   []string `json:"denyRead"`
	}
	type templateConfig struct {
		Filesystem fsConfig `json:"filesystem"`
	}

	cfg := templateConfig{
		Filesystem: fsConfig{
			AllowWrite: allowWrite,
			DenyWrite:  getDangerousFilePatterns(),
			DenyRead:   getSensitiveReadPatterns(),
		},
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("// Learned template for %q\n", cmdName))
	sb.WriteString(fmt.Sprintf("// Generated by: greywall --learning -- %s\n", cmdName))
	sb.WriteString("// Review and adjust paths as needed\n")
	sb.Write(data)
	sb.WriteString("\n")

	return sb.String()
}
