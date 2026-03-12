package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"terraform", "pulumi"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.terraform.d", "~/.config/pulumi", "~/.pulumi"},
					AllowWrite: []string{"~/.terraform.d", "~/.config/pulumi", "~/.pulumi"},
				},
			}
		},
	})
}
