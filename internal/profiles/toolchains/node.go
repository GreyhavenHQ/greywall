package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"node", "npm", "npx", "yarn", "pnpm", "bun", "deno"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead: []string{
						"~/.nvm", "~/.fnm", "~/.npm", "~/.npmrc",
						"~/.config/npm", "~/.cache/npm", "~/.cache/node",
						"~/.node-gyp", "~/.cache/node-gyp",
						"~/.pnpm-store", "~/.config/pnpm", "~/.local/share/pnpm", "~/.local/state/pnpm",
						"~/.yarn", "~/.yarnrc", "~/.yarnrc.yml", "~/.config/yarn", "~/.cache/yarn",
						"~/.cache/node/corepack", "~/.config/configstore",
						"~/.cache/turbo", "~/.cache/prisma", "~/.volta",
						"~/.bun", "~/.cache/deno", "~/.deno",
					},
					AllowWrite: []string{
						"~/.nvm", "~/.fnm", "~/.npm", "~/.npmrc",
						"~/.config/npm", "~/.cache/npm", "~/.cache/node",
						"~/.node-gyp", "~/.cache/node-gyp",
						"~/.pnpm-store", "~/.config/pnpm", "~/.local/share/pnpm", "~/.local/state/pnpm",
						"~/.yarn", "~/.config/yarn", "~/.cache/yarn",
						"~/.cache/node/corepack", "~/.config/configstore",
						"~/.cache/turbo", "~/.cache/prisma", "~/.volta",
						"~/.bun", "~/.cache/deno", "~/.deno",
					},
				},
			}
		},
	})
}
