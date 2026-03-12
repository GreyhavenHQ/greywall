package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"amp"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.amp", "~/.config/amp", "~/.cache/amp", "~/.local/share/amp", "~/.local/state/amp", "~/.claude"},
					AllowWrite: []string{"~/.amp", "~/.config/amp", "~/.cache/amp", "~/.local/share/amp", "~/.local/state/amp"},
				},
			}
		},
	})
}
