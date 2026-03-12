package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"docker", "podman", "kubectl", "helm"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.docker", "~/.config/containers", "~/.kube", "~/.config/helm", "~/.cache/helm"},
					AllowWrite: []string{"~/.docker", "~/.config/containers", "~/.kube", "~/.config/helm", "~/.cache/helm"},
				},
			}
		},
	})
}
