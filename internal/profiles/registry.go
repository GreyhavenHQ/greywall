// Package profiles provides built-in sandbox profiles for known AI coding agents.
package profiles

import (
	"sort"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// AgentDef is everything needed to define a known agent profile.
// Each agent file in the agents/ subpackage creates one of these and
// passes it to Register() via an init() function, so adding a new agent
// is a single self-contained file.
type AgentDef struct {
	// Names lists every command-line name that should resolve to this agent.
	// The first entry is the canonical name used for display and templates.
	Names []string

	// Overlay returns the agent-specific config that gets merged on top of
	// BaseProfile(). Only filesystem paths should be set here.
	Overlay func() *config.Config
}

var registry []AgentDef

// Register adds an agent definition to the global registry.
// Called from init() in each agents/*.go file.
func Register(def AgentDef) {
	registry = append(registry, def)
}

// IsKnownAgent returns the canonical agent name if cmd matches a registered
// agent, or empty string if not.
func IsKnownAgent(cmd string) string {
	for _, def := range registry {
		for _, name := range def.Names {
			if name == cmd {
				return def.Names[0]
			}
		}
	}
	return ""
}

// GetAgentProfile returns the merged base + agent overlay for a canonical name.
// Returns nil if the agent is not registered.
func GetAgentProfile(canonical string) *config.Config {
	for _, def := range registry {
		if def.Names[0] == canonical {
			return config.Merge(BaseProfile(), def.Overlay())
		}
	}
	return nil
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

// AdHocCommands is the set of common unix commands that should not trigger
// the first-run agent profile prompt.
var AdHocCommands = map[string]bool{
	"ls": true, "cat": true, "grep": true, "rg": true, "find": true,
	"head": true, "tail": true, "wc": true, "sort": true, "uniq": true,
	"sed": true, "awk": true, "cut": true, "tr": true, "tee": true,
	"echo": true, "printf": true, "env": true, "printenv": true,
	"curl": true, "wget": true, "ssh": true, "scp": true, "rsync": true,
	"git": true, "gh": true, "glab": true, "svn": true, "hg": true,
	"make": true, "cmake": true, "ninja": true, "just": true,
	"npm": true, "npx": true, "yarn": true, "pnpm": true, "bun": true, "deno": true, "node": true,
	"python": true, "python3": true, "pip": true, "pip3": true, "uv": true, "pipx": true,
	"go": true, "cargo": true, "rustc": true, "rustup": true,
	"docker": true, "podman": true, "kubectl": true, "helm": true,
	"terraform": true, "pulumi": true,
	"java": true, "javac": true, "mvn": true, "gradle": true,
	"ruby": true, "gem": true, "bundle": true,
	"bash": true, "zsh": true, "sh": true, "fish": true,
	"vim": true, "nvim": true, "nano": true, "emacs": true,
	"less": true, "more": true, "bat": true,
	"tar": true, "zip": true, "unzip": true, "gzip": true,
	"cp": true, "mv": true, "rm": true, "mkdir": true, "rmdir": true, "touch": true,
	"chmod": true, "chown": true, "ln": true,
	"ps": true, "top": true, "htop": true, "kill": true,
	"man": true, "which": true, "whereis": true, "whoami": true,
	"date": true, "cal": true, "df": true, "du": true, "free": true,
}

// IsAdHocCommand returns true if cmd is a common unix command.
func IsAdHocCommand(cmd string) bool {
	return AdHocCommands[cmd]
}
