package toolchains

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"ruby", "gem", "bundle"},
		Toolchain: true,
		Overlay: func() *config.Config {
			allowRead := []string{"~/.gem", "~/.bundle", "~/.rbenv", "~/.rvm", "~/.config/gem"}
			if runtime.GOOS == "darwin" {
				// macOS ships a system Ruby under /Library/Ruby
				allowRead = append(allowRead,
					"/Library/Ruby",
				)
			}
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: []string{"~/.gem", "~/.bundle", "~/.rbenv", "~/.rvm", "~/.config/gem"},
				},
			}
		},
	})
}
