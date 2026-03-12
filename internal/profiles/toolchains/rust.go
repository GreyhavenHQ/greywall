package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"cargo", "rustc", "rustup"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.cargo", "~/.rustup", "~/.cache/cargo", "~/.cache/sccache", "~/.config/cargo"},
					AllowWrite: []string{"~/.cargo", "~/.rustup", "~/.cache/cargo", "~/.cache/sccache", "~/.config/cargo"},
				},
			}
		},
	})
}
