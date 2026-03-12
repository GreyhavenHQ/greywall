package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"java", "javac", "mvn", "gradle"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  []string{"~/.m2", "~/.gradle", "~/.java", "~/.sdkman", "~/.config/jgit"},
					AllowWrite: []string{"~/.m2", "~/.gradle", "~/.java", "~/.sdkman", "~/.config/jgit"},
				},
			}
		},
	})
}
