package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"pi"},
		Overlay: func() *config.Config {
			allowRead := []string{"~/.pi", "~/.config/pi", "~/.cache/pi"}
			if runtime.GOOS == "darwin" {
				allowRead = append(allowRead, "~/Library")
			}
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: []string{"~/.pi", "~/.config/pi", "~/.cache/pi"},
				},
			}
		},
	})
}
