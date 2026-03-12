package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"claude", "claude-code"},
		Overlay: func() *config.Config {
			allowRead := []string{
				"~/.claude",
				"~/.claude.json",
				"~/.claude.json.*",
				"~/.config/claude",
				"~/.local/share/claude",
				"~/.local/state/claude",
				"~/.mcp.json",
			}
			allowWrite := []string{
				"~/.claude",
				"~/.claude.json",
				"~/.claude.lock",
				"~/.cache/claude",
				"~/.config/claude",
				"~/.local/state/claude",
				"~/.local/share/claude",
				"~/.mcp.json",
			}
			if runtime.GOOS == "darwin" {
				allowRead = append(allowRead,
					"~/Library/Application Support/Claude/claude_desktop_config.json",
					"/Library/Application Support/ClaudeCode/managed-settings.json",
					"/Library/Application Support/ClaudeCode/managed-mcp.json",
					"/Library/Application Support/ClaudeCode/CLAUDE.md",
				)
			}
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: allowWrite,
				},
			}
		},
	})
}
