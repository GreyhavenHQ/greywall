package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"gemini"},
		Overlay: func() *config.Config {
			allowRead := []string{"~/.gemini", "~/.cache/gemini"}
			if runtime.GOOS == "darwin" {
				allowRead = append(allowRead,
					"/Library/Application Support/GeminiCli",
				)
			}
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: []string{"~/.gemini", "~/.cache/gemini"},
				},
			}
		},
	})
}
