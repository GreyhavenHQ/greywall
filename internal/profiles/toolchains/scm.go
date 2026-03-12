package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"gh", "glab"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead: []string{
						"~/.config/gh", "~/.cache/gh", "~/.local/share/gh", "~/.local/state/gh",
						"~/.config/glab-cli", "~/.cache/glab-cli", "~/.local/share/glab-cli", "~/.local/state/glab-cli",
					},
					AllowWrite: []string{
						"~/.config/gh", "~/.cache/gh", "~/.local/share/gh", "~/.local/state/gh",
						"~/.config/glab-cli", "~/.cache/glab-cli", "~/.local/share/glab-cli", "~/.local/state/glab-cli",
					},
				},
			}
		},
	})
}
