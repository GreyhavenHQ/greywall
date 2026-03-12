package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"cursor", "cursor-agent"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.cursor", "~/.config/cursor", "~/.local/share/cursor-agent"},
					AllowWrite: []string{"~/.cursor", "~/.config/cursor", "~/.cache/cursor-compile-cache", "~/.local/share/cursor-agent"},
				},
			}
		},
	})
}
