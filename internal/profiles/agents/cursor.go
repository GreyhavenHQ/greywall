package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"cursor", "cursor-agent"},
		Overlay: func() *config.Config {
			allowRead := []string{"~/.cursor", "~/.config/cursor", "~/.local/share/cursor-agent"}
			allowWrite := []string{"~/.cursor", "~/.config/cursor", "~/.cache/cursor-compile-cache", "~/.local/share/cursor-agent"}
			if runtime.GOOS == "darwin" {
				allowRead = append(allowRead,
					"~/Library/Application Support/Cursor",
					"/Applications/Cursor.app",
				)
				allowWrite = append(allowWrite,
					"~/Library/Caches/cursor-compile-cache",
				)
			}
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: allowWrite,
				},
			}
		},
	})
}
