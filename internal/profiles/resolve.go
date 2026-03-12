package profiles

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

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
//   - A saved profile already exists for the command
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
			fmt.Fprintf(os.Stderr, "[greywall] No saved profile for %q. Run with --learning to create one.\n", cmdName)
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
		fmt.Fprintf(os.Stderr, "[greywall] A built-in profile for %q is available. Use --auto-profile to apply it.\n", cmdName)
		return nil, nil
	}

	profile := GetAgentProfile(canonical)
	if profile == nil {
		return nil, nil
	}

	response := PromptFirstRun(cmdName, profile, os.Stderr, os.Stdin)

	switch response {
	case PromptYes:
		if saveErr := SaveAsTemplate(profile, cmdName, debug); saveErr != nil {
			fmt.Fprintf(os.Stderr, "[greywall] Warning: could not save profile: %v\n", saveErr)
		}
		return profile, nil

	case PromptEdit:
		if saveErr := SaveAsTemplate(profile, cmdName, debug); saveErr != nil {
			return nil, fmt.Errorf("could not save profile for editing: %w", saveErr)
		}
		templatePath := sandbox.LearnedTemplatePath(cmdName)
		edited, editErr := editAndValidate(templatePath)
		if editErr != nil {
			fmt.Fprintf(os.Stderr, "[greywall] Warning: could not open editor: %v\n", editErr)
			fmt.Fprintf(os.Stderr, "[greywall] Edit manually: %s\n", templatePath)
			return profile, nil
		}
		if edited == nil {
			return profile, nil
		}
		return edited, nil

	case PromptNever:
		if suppressErr := AddSuppression(cmdName); suppressErr != nil {
			fmt.Fprintf(os.Stderr, "[greywall] Warning: could not save preference: %v\n", suppressErr)
		}
		return nil, nil

	default:
		return nil, nil
	}
}

// editAndValidate opens the editor on the profile, validates the result,
// and re-opens the editor if validation fails. Returns the loaded config
// or nil if the user chooses to skip.
func editAndValidate(path string) (*config.Config, error) {
	for {
		if err := openEditor(path); err != nil {
			return nil, err
		}
		cfg, loadErr := config.Load(path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "[greywall] Profile has errors: %v\n", loadErr)
			fmt.Fprintf(os.Stderr, "[greywall] [e] Edit again   [x] Use original profile\n")
			fmt.Fprintf(os.Stderr, "> ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return nil, nil
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer == "e" || answer == "" {
				continue
			}
			return nil, nil
		}
		return cfg, nil
	}
}

// openEditor opens the user's preferred editor on the given file path.
// It waits for the editor to exit before returning.
func openEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command(editor, path) //nolint:gosec // user's own EDITOR - intentional
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// profileFS is the minimal struct used for saved profiles on disk.
// Only filesystem fields are persisted, matching the format used by --learning.
type profileFS struct {
	AllowRead  []string `json:"allowRead,omitempty"`
	AllowWrite []string `json:"allowWrite"`
	DenyWrite  []string `json:"denyWrite"`
	DenyRead   []string `json:"denyRead"`
}

type profileConfig struct {
	Filesystem profileFS `json:"filesystem"`
}

// SaveAsTemplate serializes a profile config to disk so it auto-loads on
// subsequent runs without prompting. Only filesystem paths are persisted,
// matching the format produced by --learning.
func SaveAsTemplate(cfg *config.Config, cmdName string, debug bool) error {
	p := profileConfig{
		Filesystem: profileFS{
			AllowRead:  nonNil(cfg.Filesystem.AllowRead),
			AllowWrite: nonNil(cfg.Filesystem.AllowWrite),
			DenyWrite:  nonNil(cfg.Filesystem.DenyWrite),
			DenyRead:   nonNil(cfg.Filesystem.DenyRead),
		},
	}

	savePath := sandbox.LearnedTemplatePath(cmdName)
	if err := os.MkdirAll(filepath.Dir(savePath), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	var content []byte
	content = fmt.Appendf(content, "// Built-in profile for %q\n", cmdName)
	content = append(content, "// Review and adjust paths as needed\n"...)
	content = append(content, data...)
	content = append(content, '\n')

	if err := os.WriteFile(savePath, content, 0o600); err != nil {
		return err
	}
	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Saved profile: %s\n", savePath)
	}
	fmt.Fprintf(os.Stderr, "[greywall] Profile saved. Edit with: greywall profiles show %s\n", cmdName)
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
// that do not yet have a saved profile.
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
