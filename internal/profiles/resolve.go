package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/sandbox"
)

// ResolveFirstRun checks whether a first-run profile prompt should be shown
// for the given command. It returns a config to merge if the user accepts,
// or nil if no profile should be applied.
//
// The prompt is skipped when:
//   - cmdName is empty or an ad-hoc command (ls, curl, etc.)
//   - cmdName is not a known agent
//   - A learned template already exists for the command
//   - The user previously chose "never" for this command
//   - stdin is not a terminal (pipe/CI)
func ResolveFirstRun(cmdName string, hasTemplate bool, debug bool) (*config.Config, error) {
	if cmdName == "" {
		return nil, nil
	}

	if IsAdHocCommand(cmdName) {
		return nil, nil
	}

	canonical := IsKnownAgent(cmdName)
	if canonical == "" {
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall] No learned template for %q. Run with --learning to create one.\n", cmdName)
		}
		return nil, nil
	}

	if hasTemplate {
		return nil, nil
	}

	prefs, err := LoadPreferences()
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to load preferences: %v\n", err)
		}
		prefs = &Preferences{}
	}

	if prefs.IsPromptSuppressed(cmdName) {
		return nil, nil
	}

	if !IsInteractive() {
		return nil, nil
	}

	profile := GetAgentProfile(canonical)
	if profile == nil {
		return nil, nil
	}

	response := PromptFirstRun(cmdName, os.Stderr, os.Stdin)

	switch response {
	case PromptYes:
		if saveErr := SaveAsTemplate(profile, cmdName, debug); saveErr != nil {
			fmt.Fprintf(os.Stderr, "[greywall] Warning: could not save profile as template: %v\n", saveErr)
		}
		return profile, nil

	case PromptNever:
		if suppressErr := AddSuppression(cmdName); suppressErr != nil {
			fmt.Fprintf(os.Stderr, "[greywall] Warning: could not save preference: %v\n", suppressErr)
		}
		return nil, nil

	default:
		return nil, nil
	}
}

// templateFS is the minimal struct used for learned templates on disk.
// Only filesystem fields are persisted, matching the format used by --learning.
type templateFS struct {
	AllowRead  []string `json:"allowRead,omitempty"`
	AllowWrite []string `json:"allowWrite"`
	DenyWrite  []string `json:"denyWrite"`
	DenyRead   []string `json:"denyRead"`
}

type templateConfig struct {
	Filesystem templateFS `json:"filesystem"`
}

// SaveAsTemplate serializes a profile config as a learned template so it
// auto-loads on subsequent runs without prompting. Only filesystem paths
// are persisted, matching the format produced by --learning.
func SaveAsTemplate(cfg *config.Config, cmdName string, debug bool) error {
	tmpl := templateConfig{
		Filesystem: templateFS{
			AllowRead:  nonNil(cfg.Filesystem.AllowRead),
			AllowWrite: nonNil(cfg.Filesystem.AllowWrite),
			DenyWrite:  nonNil(cfg.Filesystem.DenyWrite),
			DenyRead:   nonNil(cfg.Filesystem.DenyRead),
		},
	}

	templatePath := sandbox.LearnedTemplatePath(cmdName)
	if err := os.MkdirAll(filepath.Dir(templatePath), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tmpl, "", "  ")
	if err != nil {
		return err
	}

	var content []byte
	content = fmt.Appendf(content, "// Built-in profile for %q\n", cmdName)
	content = append(content, "// Review and adjust paths as needed\n"...)
	content = append(content, data...)
	content = append(content, '\n')

	if err := os.WriteFile(templatePath, content, 0o600); err != nil {
		return err
	}
	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Saved profile as template: %s\n", templatePath)
	}
	fmt.Fprintf(os.Stderr, "[greywall] Profile saved. Edit with: greywall templates show %s\n", cmdName)
	return nil
}

// nonNil returns the slice as-is if non-nil, or an empty slice.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ListAvailableProfiles returns a sorted list of built-in agent profiles
// that do not yet have a saved learned template.
func ListAvailableProfiles() []string {
	saved := make(map[string]bool)
	templates, _ := sandbox.ListLearnedTemplates()
	for _, t := range templates {
		saved[t.Name] = true
	}

	var available []string
	for _, agent := range AvailableAgents() {
		if !saved[agent] {
			available = append(available, agent)
		}
	}
	sort.Strings(available)
	return available
}
