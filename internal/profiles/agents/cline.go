package agents

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names: []string{"cline"},
		Overlay: func() *config.Config {
			allowRead := []string{"~/.cline", "~/.config/cline", "~/.cache/cline", "~/.local/share/cline", "~/.local/state/cline"}
			allowWrite := []string{"~/.cline", "~/.config/cline", "~/.cache/cline", "~/.local/share/cline", "~/.local/state/cline"}
			if runtime.GOOS == "darwin" {
				vsCodeCline := "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev"
				allowRead = append(allowRead, vsCodeCline)
				allowWrite = append(allowWrite, vsCodeCline)
			}
			return &config.Config{
				Network: config.NetworkConfig{
					Rules: []config.NetworkRule{
						{Destination: "api.anthropic.com", Port: "443", Action: "allow"},
						{Destination: "api.openai.com", Port: "443", Action: "allow"},
					},
				},
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: allowWrite,
				},
			}
		},
	})
}
