// Package profiles provides built-in sandbox profiles for known AI coding agents.
package profiles

import (
	"sort"
	"strings"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// KeyringLookup defines how to retrieve a secret from the system keyring.
// On Linux, this uses secret-tool to read from gnome-keyring via libsecret.
type KeyringLookup struct {
	// Service is the attribute value for "service" passed to secret-tool lookup.
	// Example: "gh:github.com" retrieves the GitHub CLI OAuth token.
	Service string
}

// AgentDef is everything needed to define a known agent or toolchain profile.
// Each file in the agents/ subpackage creates one of these and passes it to
// Register() via an init() function, so adding a new entry is a single
// self-contained file.
type AgentDef struct {
	// Names lists every command-line name that should resolve to this profile.
	// The first entry is the canonical name used for display and profiles.
	Names []string

	// Toolchain marks this as a toolchain profile (npm, uv, cargo, etc.)
	// rather than an AI agent. Toolchain profiles are not merged with
	// BaseProfile(); they only provide their own filesystem paths.
	Toolchain bool

	// Overlay returns the profile-specific config. For agents this is merged
	// on top of BaseProfile(); for toolchains it is used as-is.
	Overlay func() *config.Config

	// KeyringSecrets maps environment variable names to keyring lookups.
	// On Linux, greywall reads these from the host keyring at startup (before
	// sandboxing) and injects them as environment variables. This avoids
	// exposing the D-Bus session bus (and gnome-keyring) inside the sandbox.
	// Ignored on macOS (keychain is accessible via file-based access).
	KeyringSecrets map[string]KeyringLookup
}

var registry []AgentDef

// Register adds an agent definition to the global registry.
// Called from init() in each agents/*.go file.
func Register(def AgentDef) {
	registry = append(registry, def)
}

// IsKnownAgent returns the canonical agent name if cmd matches a registered
// agent, or empty string if not. Matching is case-insensitive so that
// "Claude" (macOS desktop app) resolves to the same profile as "claude" (CLI).
func IsKnownAgent(cmd string) string {
	lower := strings.ToLower(cmd)
	for _, def := range registry {
		for _, name := range def.Names {
			if strings.ToLower(name) == lower {
				return def.Names[0]
			}
		}
	}
	return ""
}

// GetAgentProfile returns the profile for a canonical name.
// For agents, the overlay is merged on top of BaseProfile().
// For toolchains, the overlay is returned as-is.
// Returns nil if not registered.
func GetAgentProfile(canonical string) *config.Config {
	for _, def := range registry {
		if def.Names[0] == canonical {
			overlay := def.Overlay()
			if def.Toolchain {
				return overlay
			}
			return config.Merge(BaseProfile(), overlay)
		}
	}
	return nil
}

// IsToolchain returns true if the canonical name is a toolchain profile.
func IsToolchain(canonical string) bool {
	for _, def := range registry {
		if def.Names[0] == canonical {
			return def.Toolchain
		}
	}
	return false
}

// AvailableAgents returns a sorted list of canonical agent names.
func AvailableAgents() []string {
	agents := make([]string, 0, len(registry))
	for _, def := range registry {
		agents = append(agents, def.Names[0])
	}
	sort.Strings(agents)
	return agents
}

// GetKeyringSecrets returns all keyring secret mappings for the given canonical name.
// Returns nil if the profile has no keyring secrets.
func GetKeyringSecrets(canonical string) map[string]KeyringLookup {
	for _, def := range registry {
		if def.Names[0] == canonical && len(def.KeyringSecrets) > 0 {
			return def.KeyringSecrets
		}
	}
	return nil
}

// AdHocCommands is the set of basic unix utilities that should not trigger
// the first-run profile prompt. These are simple commands that don't need
// their own config/cache directories. Toolchain commands (npm, uv, cargo,
// etc.) are NOT here; they have their own profiles under agents/.
var AdHocCommands = map[string]bool{
	// Text processing
	"ls": true, "cat": true, "grep": true, "rg": true, "find": true,
	"head": true, "tail": true, "wc": true, "sort": true, "uniq": true,
	"sed": true, "awk": true, "cut": true, "tr": true, "tee": true,
	"less": true, "more": true, "bat": true,
	// Output
	"echo": true, "printf": true, "env": true, "printenv": true,
	// File operations
	"cp": true, "mv": true, "rm": true, "mkdir": true, "rmdir": true, "touch": true,
	"chmod": true, "chown": true, "ln": true,
	// Archives
	"tar": true, "zip": true, "unzip": true, "gzip": true,
	// Network utilities
	"curl": true, "wget": true, "ssh": true, "scp": true, "rsync": true,
	// VCS
	"git": true, "svn": true, "hg": true,
	// Build
	"make": true, "cmake": true, "ninja": true, "just": true,
	// Shells
	"bash": true, "zsh": true, "sh": true, "fish": true,
	// Editors
	"vim": true, "nvim": true, "nano": true, "emacs": true,
	// System info
	"ps": true, "top": true, "htop": true, "kill": true,
	"man": true, "which": true, "whereis": true, "whoami": true,
	"date": true, "cal": true, "df": true, "du": true, "free": true,
}

// IsAdHocCommand returns true if cmd is a common unix command.
func IsAdHocCommand(cmd string) bool {
	return AdHocCommands[cmd]
}
