package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"goose"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.goose", "~/.config/goose", "~/.cache/goose", "~/.local/share/goose", "~/.local/state/goose"},
					AllowWrite: []string{"~/.goose", "~/.config/goose", "~/.cache/goose", "~/.local/share/goose", "~/.local/state/goose"},
				},
			}
		},
	})
}
