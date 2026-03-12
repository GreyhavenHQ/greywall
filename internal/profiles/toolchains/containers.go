package toolchains

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"docker", "podman", "kubectl", "helm"},
		Toolchain: true,
		Overlay: func() *config.Config {
			allowRead := []string{"~/.docker", "~/.config/containers", "~/.kube", "~/.config/helm", "~/.cache/helm"}
			allowWrite := []string{"~/.docker", "~/.config/containers", "~/.kube", "~/.config/helm", "~/.cache/helm"}
			if runtime.GOOS == "darwin" {
				// macOS Docker alternatives: OrbStack, Colima, Rancher Desktop
				allowRead = append(allowRead,
					"~/.orbstack",
					"~/.colima",
					"~/.rd",
				)
				allowWrite = append(allowWrite,
					"~/.orbstack",
					"~/.colima",
					"~/.rd",
				)
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
