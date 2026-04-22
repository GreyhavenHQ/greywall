package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"copilot"},
		Overlay: func() *config.Config {
			return &config.Config{
				Network: config.NetworkConfig{
					Rules: []config.NetworkRule{
						{Destination: "api.github.com", Port: "443", Action: "allow"},
						{Destination: "**.githubusercontent.com", Port: "443", Action: "allow"},
						{Destination: "github.com", Port: "443", Action: "allow"},
					},
				},
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.copilot"},
					AllowWrite: []string{"~/.copilot"},
				},
			}
		},
	})
}
