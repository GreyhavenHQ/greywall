package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"aider"},
		Overlay: func() *config.Config {
			return &config.Config{
				Network: config.NetworkConfig{
					Rules: []config.NetworkRule{
						{Destination: "api.openai.com", Port: "443", Action: "allow"},
						{Destination: "api.anthropic.com", Port: "443", Action: "allow"},
					},
				},
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.aider*", "~/.config/aider", "~/.cache/aider", "~/.local/share/aider"},
					AllowWrite: []string{"~/.aider*", "~/.config/aider", "~/.cache/aider", "~/.local/share/aider"},
				},
			}
		},
	})
}
