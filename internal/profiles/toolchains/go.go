package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"go"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead: []string{
						"~/go", "~/.cache/go-build", "~/.config/go",
						"~/.config/golangci-lint", "~/.cache/golangci-lint",
						"~/.cache/gopls", "~/.goenv", "~/.local/share/go",
					},
					AllowWrite: []string{
						"~/go", "~/.cache/go-build", "~/.config/go",
						"~/.config/golangci-lint", "~/.cache/golangci-lint",
						"~/.cache/gopls", "~/.goenv", "~/.local/share/go",
					},
				},
			}
		},
	})
}
