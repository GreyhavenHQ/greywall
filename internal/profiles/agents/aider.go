package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"aider"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.aider*", "~/.config/aider", "~/.cache/aider", "~/.local/share/aider"},
					AllowWrite: []string{"~/.aider*", "~/.config/aider", "~/.cache/aider", "~/.local/share/aider"},
				},
			}
		},
	})
}
