package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"codex"},
		Overlay: func() *config.Config {
			allowRead := []string{"~/.codex", "~/.cache/codex"}
			if runtime.GOOS == "darwin" {
				allowRead = append(allowRead,
					"~/Library/Preferences/com.openai.codex.plist",
					"/Library/Preferences/com.openai.codex.plist",
					"/Library/Managed Preferences/com.openai.codex.plist",
					"/etc/codex",
				)
			}
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: []string{"~/.codex", "~/.cache/codex"},
				},
			}
		},
	})
}
