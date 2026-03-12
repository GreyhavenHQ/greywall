package profiles

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// PromptResponse represents the user's answer to the first-run prompt.
type PromptResponse int

const (
	PromptYes   PromptResponse = iota // Use profile
	PromptEdit                        // Save profile, open editor, then load
	PromptNo                          // Skip, use restrictive defaults
	PromptNever                       // Suppress future prompts for this command
)

// ANSI color codes.
const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"
	ansiGreen = "\033[32m"
	ansiRed   = "\033[31m"
	ansiCyan  = "\033[36m"
)

// colorizer wraps an io.Writer with optional ANSI color support.
// Colors are only emitted when the writer is a terminal.
type colorizer struct {
	w     io.Writer
	color bool
}

func newColorizer(w io.Writer) colorizer {
	useColor := false
	if f, ok := w.(*os.File); ok {
		useColor = isTerminal(f)
	}
	// Respect NO_COLOR convention
	if os.Getenv("NO_COLOR") != "" {
		useColor = false
	}
	return colorizer{w: w, color: useColor}
}

func (c colorizer) styled(code, text string) string {
	if !c.color {
		return text
	}
	return code + text + ansiReset
}

func (c colorizer) bold(text string) string  { return c.styled(ansiBold, text) }
func (c colorizer) green(text string) string { return c.styled(ansiGreen, text) }
func (c colorizer) red(text string) string   { return c.styled(ansiRed, text) }
func (c colorizer) cyan(text string) string  { return c.styled(ansiCyan, text) }
func (c colorizer) dim(text string) string   { return c.styled(ansiDim, text) }

// isTerminal returns true if the given file is a terminal.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// IsInteractive returns true if stdin is a terminal (not a pipe or redirection).
func IsInteractive() bool {
	return isTerminal(os.Stdin)
}

// formatPaths returns a display string for a list of paths.
// Keeps prefixes (~/,  ./) so users know whether paths are relative or in $HOME.
// The working dir entry "." is excluded (shown separately as a suffix).
func formatPaths(paths []string) string {
	display := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "." {
			continue
		}
		display = append(display, p)
	}
	return strings.Join(display, "  ")
}

// hasWorkingDir returns true if "." is in the paths list.
func hasWorkingDir(paths []string) bool {
	for _, p := range paths {
		if p == "." {
			return true
		}
	}
	return false
}

// PromptFirstRun shows the profile summary and asks the user how to proceed.
func PromptFirstRun(agentName string, profile *config.Config, w io.Writer, r io.Reader) PromptResponse {
	c := newColorizer(w)

	//nolint:errcheck,gosec // terminal UI output, errors are non-actionable
	fmt.Fprintf(w, "%s Running %s in a sandbox.\n",
		c.bold("[greywall]"), c.cyan(agentName))
	fmt.Fprintf(w, "A built-in profile is available. Without it, only the current directory is accessible.\n") //nolint:errcheck
	fmt.Fprintln(w)                                                                                            //nolint:errcheck

	// Show what the profile grants
	if len(profile.Filesystem.AllowRead) > 0 {
		suffix := ""
		if hasWorkingDir(profile.Filesystem.AllowRead) {
			suffix = c.dim(" + working dir")
		}
		fmt.Fprintf(w, "%s  %s%s\n", c.green("Allow read: "), formatPaths(profile.Filesystem.AllowRead), suffix) //nolint:errcheck,gosec
	}
	if len(profile.Filesystem.AllowWrite) > 0 {
		suffix := ""
		if hasWorkingDir(profile.Filesystem.AllowWrite) {
			suffix = c.dim(" + working dir")
		}
		fmt.Fprintf(w, "%s %s%s\n", c.green("Allow write:"), formatPaths(profile.Filesystem.AllowWrite), suffix) //nolint:errcheck,gosec
	}
	if len(profile.Filesystem.DenyRead) > 0 {
		fmt.Fprintf(w, "%s   %s\n", c.red("Deny read:"), formatPaths(profile.Filesystem.DenyRead)) //nolint:errcheck,gosec
	}
	if len(profile.Filesystem.DenyWrite) > 0 {
		fmt.Fprintf(w, "%s  %s\n", c.red("Deny write:"), formatPaths(profile.Filesystem.DenyWrite)) //nolint:errcheck,gosec
	}

	fmt.Fprintln(w) //nolint:errcheck
	//nolint:errcheck,gosec // terminal UI output
	fmt.Fprintf(w, "%s Use profile %s   %s Edit first   %s Skip %s   %s Don't ask again\n",
		c.bold("[Y]"), c.dim("(recommended)"), c.bold("[e]"), c.bold("[s]"), c.dim("(restrictive)"), c.bold("[n]"))
	fmt.Fprintf(w, "%s ", c.bold(">")) //nolint:errcheck,gosec

	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return PromptNo
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	switch answer {
	case "", "y", "yes":
		return PromptYes
	case "e", "edit":
		return PromptEdit
	case "s", "skip":
		return PromptNo
	case "n", "no", "never":
		return PromptNever
	default:
		return PromptNo
	}
}
