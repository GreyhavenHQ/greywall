package profiles

import "github.com/GreyhavenHQ/greywall/internal/config"

// BaseProfile returns the universal "code" profile shared by all agents.
// It provides access to git config, SSH config (not keys), shared agent
// context files, and SCM CLI state directories.
func BaseProfile() *config.Config {
	useDefaults := true
	return &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowRead: []string{
				".",
				"~/CLAUDE.md",
				"~/AGENTS.md",
				"~/.gitconfig",
				"~/.gitignore",
				"~/.config/git",
				"~/.ssh/config",
				"~/.ssh/known_hosts",
				"~/.ssh/allowed_signers",
				// Shared agent context
				"~/.skills",
				"~/.agents",
				"~/.claude/agents",
				"~/.claude/skills",
				// SCM CLIs
				"~/.config/gh",
				"~/.config/glab-cli",
			},
			AllowWrite: []string{
				".",
				"~/.skills",
				"~/.agents",
				"~/AGENTS.md",
				// SCM CLI state
				"~/.config/gh",
				"~/.cache/gh",
				"~/.local/share/gh",
				"~/.local/state/gh",
				// SSH known_hosts
				"~/.ssh/known_hosts",
			},
			DenyRead: []string{
				"~/.ssh/id_*",
				"~/.gnupg/**",
				".env",
				".env.*",
			},
			DenyWrite: []string{
				"~/.bashrc",
				"~/.bash_profile",
				"~/.zshrc",
				"~/.zprofile",
				"~/.profile",
				"~/.ssh",
				"~/.gnupg",
			},
		},
		Command: config.CommandConfig{
			UseDefaults: &useDefaults,
		},
	}
}
