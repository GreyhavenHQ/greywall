package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"goose"},
		Overlay: func() *config.Config {
			allowRead := []string{"~/.goose", "~/.config/goose", "~/.cache/goose", "~/.local/share/goose", "~/.local/state/goose"}
			allowWrite := []string{"~/.goose", "~/.config/goose", "~/.cache/goose", "~/.local/share/goose", "~/.local/state/goose"}
			if runtime.GOOS == "darwin" {
				macPath := "~/Library/Application Support/Block.goose"
				allowRead = append(allowRead, macPath)
				allowWrite = append(allowWrite, macPath)
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
