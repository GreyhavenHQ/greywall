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
				allowRead = append(
					allowRead,
					"/Library/Application Support/GeminiCli",
				)
			}
			return &config.Config{
				Network: config.NetworkConfig{
					Rules: []config.NetworkRule{
						{Destination: "generativelanguage.googleapis.com", Port: "443", Action: "allow"},
						{Destination: "play.googleapis.com", Port: "443", Action: "allow"},
					},
				},
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: []string{"~/.gemini", "~/.cache/gemini"},
				},
			}
		},
	})
}
