package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"kilo", "kilocode"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.kilocode", "~/.roo", "~/.config/kilo", "~/.cache/kilo", "~/.local/share/kilo", "~/.local/state/kilo"},
					AllowWrite: []string{"~/.kilocode", "~/.roo", "~/.config/kilo", "~/.cache/kilo", "~/.local/share/kilo", "~/.local/state/kilo"},
				},
			}
		},
	})
}
