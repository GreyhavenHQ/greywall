package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"kilo", "kilocode"},
		Overlay: func() *config.Config {
			allowRead := []string{"~/.kilocode", "~/.roo", "~/.config/kilo", "~/.cache/kilo", "~/.local/share/kilo", "~/.local/state/kilo"}
			allowWrite := []string{"~/.kilocode", "~/.roo", "~/.config/kilo", "~/.cache/kilo", "~/.local/share/kilo", "~/.local/state/kilo"}
			if runtime.GOOS == "darwin" {
				allowRead = append(allowRead,
					"/Library/Application Support/RooCode",
				)
				vsCodeKilo := "~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code"
				allowRead = append(allowRead, vsCodeKilo)
				allowWrite = append(allowWrite, vsCodeKilo)
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
