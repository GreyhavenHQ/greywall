package profiles

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// PromptResponse represents the user's answer to the first-run prompt.
type PromptResponse int

const (
	PromptYes   PromptResponse = iota // Use recommended defaults
	PromptNo                          // Continue with restrictive defaults
	PromptNever                       // Suppress future prompts for this command
)

// isTerminal returns true if the given file descriptor is a terminal.
func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// IsInteractive returns true if stdin is a terminal (not a pipe or redirection).
func IsInteractive() bool {
	return isTerminal(int(os.Stdin.Fd()))
}

// PromptFirstRun asks the user whether to use recommended defaults for a known agent.
// Returns PromptYes, PromptNo, or PromptNever.
func PromptFirstRun(agentName string, w io.Writer, r io.Reader) PromptResponse {
	fmt.Fprintf(w, "\n[greywall] No sandbox profile for %q.\n", agentName)
	fmt.Fprintf(w, "Use recommended defaults? [Y/n/never] ")

	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return PromptNo
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	switch answer {
	case "", "y", "yes":
		return PromptYes
	case "never":
		return PromptNever
	default:
		return PromptNo
	}
}
