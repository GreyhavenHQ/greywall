package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"cline"},
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.cline", "~/.config/cline", "~/.cache/cline", "~/.local/share/cline", "~/.local/state/cline"},
					AllowWrite: []string{"~/.cline", "~/.config/cline", "~/.cache/cline", "~/.local/share/cline", "~/.local/state/cline"},
				},
			}
		},
	})
}
