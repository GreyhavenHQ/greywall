package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"gh", "glab"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead: []string{
						"~/.gitconfig", "~/.gitignore", "~/.config/git",
						"~/.config/gh", "~/.cache/gh", "~/.local/share/gh", "~/.local/state/gh",
						"~/.config/glab-cli", "~/.cache/glab-cli", "~/.local/share/glab-cli", "~/.local/state/glab-cli",
					},
					AllowWrite: []string{
						"~/.config/gh", "~/.cache/gh", "~/.local/share/gh", "~/.local/state/gh",
						"~/.config/glab-cli", "~/.cache/glab-cli", "~/.local/share/glab-cli", "~/.local/state/glab-cli",
					},
				},
			}
		},
		// On Linux, gh stores its OAuth token in gnome-keyring via libsecret.
		// The D-Bus session bus (and thus the keyring) is blocked inside the sandbox.
		// Read the token on the host via secret-tool and inject it as GH_TOKEN.
		KeyringSecrets: map[string]profiles.KeyringLookup{
			"GH_TOKEN": {Service: "gh:github.com"},
		},
	})
}
