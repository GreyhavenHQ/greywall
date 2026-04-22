package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"auggie"},
		Overlay: func() *config.Config {
			return &config.Config{
				Network: config.NetworkConfig{
					Rules: []config.NetworkRule{
						{Destination: "api.openai.com", Port: "443", Action: "allow"},
						{Destination: "api.anthropic.com", Port: "443", Action: "allow"},
						{Destination: "**.augmentcode.com", Port: "443", Action: "allow"},
					},
				},
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.augment"},
					AllowWrite: []string{"~/.augment"},
				},
			}
		},
	})
}
