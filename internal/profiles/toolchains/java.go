package toolchains

import (
	"runtime"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"java", "javac", "mvn", "gradle"},
		Toolchain: true,
		Overlay: func() *config.Config {
			allowRead := []string{"~/.m2", "~/.gradle", "~/.java", "~/.sdkman", "~/.config/jgit"}
			if runtime.GOOS == "darwin" {
				allowRead = append(allowRead,
					"/Library/Java/JavaVirtualMachines",
				)
			}
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead:  allowRead,
					AllowWrite: []string{"~/.m2", "~/.gradle", "~/.java", "~/.sdkman", "~/.config/jgit"},
				},
			}
		},
	})
}
