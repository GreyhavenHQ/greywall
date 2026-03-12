package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"ruby", "gem", "bundle"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.gem", "~/.bundle", "~/.rbenv", "~/.rvm", "~/.config/gem"},
					AllowWrite: []string{"~/.gem", "~/.bundle", "~/.rbenv", "~/.rvm", "~/.config/gem"},
				},
			}
		},
	})
}
