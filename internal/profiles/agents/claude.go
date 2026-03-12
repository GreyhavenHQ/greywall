package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"claude", "claude-code"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead: []string{
						"~/.claude",
						"~/.claude.json",
						"~/.claude.json.*",
						"~/.config/claude",
						"~/.local/share/claude",
						"~/.local/state/claude",
						"~/.mcp.json",
					},
					AllowWrite: []string{
						"~/.claude",
						"~/.claude.json",
						"~/.claude.lock",
						"~/.cache/claude",
						"~/.config/claude",
						"~/.local/state/claude",
						"~/.local/share/claude",
						"~/.mcp.json",
					},
				},
			}
		},
	})
}
