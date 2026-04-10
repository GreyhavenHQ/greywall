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
				Network: config.NetworkConfig{
					Rules: []config.NetworkRule{
						{Destination: "api.openai.com", Port: "443", Action: "allow"},
						{Destination: "api.anthropic.com", Port: "443", Action: "allow"},
					},
				},
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: []string{"~/.pi", "~/.config/pi", "~/.cache/pi"},
				},
			}
		},
	})
}
