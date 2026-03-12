package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"pi"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.pi", "~/.config/pi", "~/.cache/pi"},
					AllowWrite: []string{"~/.pi", "~/.config/pi", "~/.cache/pi"},
				},
			}
		},
	})
}
