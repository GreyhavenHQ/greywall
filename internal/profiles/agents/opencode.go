package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"opencode"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead: []string{
						"~/.opencode", "~/.opencode.json", "~/.config/opencode",
						"~/.cache/opencode", "~/.local/share/opencode", "~/.local/share/opentui",
						"~/.local/state/opencode", "~/.config/github-copilot",
					},
					AllowWrite: []string{
						"~/.opencode", "~/.opencode.json", "~/.config/opencode",
						"~/.cache/opencode", "~/.local/share/opencode", "~/.local/share/opentui",
						"~/.local/state/opencode",
					},
				},
			}
		},
	})
}
