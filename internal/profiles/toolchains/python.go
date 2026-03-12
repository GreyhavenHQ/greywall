package toolchains

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	profiles.Register(profiles.AgentDef{
		Names:     []string{"python", "python3", "pip", "pip3", "uv", "uvx", "pipx"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return &config.Config{
				Filesystem: config.FilesystemConfig{
					AllowRead: []string{
						"~/.cache/pip", "~/.config/pip",
						"~/.cache/uv", "~/.config/uv", "~/.local/share/uv", "~/.local/state/uv",
						"~/.local/pipx", "~/.pyenv", "~/.virtualenvs",
						"~/.cache/pypoetry", "~/.config/pypoetry", "~/.local/share/pypoetry",
						"~/.cache/pdm", "~/.config/pdm", "~/.local/share/pdm",
						"~/.cache/pre-commit", "~/.cache/mypy", "~/.cache/ruff",
						"~/.conda", "~/.condarc", "~/miniconda3", "~/miniforge3",
						"~/.cache/hatch", "~/.config/hatch", "~/.local/share/hatch",
						"~/.ipython", "~/.jupyter", "~/.python_history",
					},
					AllowWrite: []string{
						"~/.cache/pip", "~/.config/pip",
						"~/.cache/uv", "~/.config/uv", "~/.local/share/uv", "~/.local/state/uv",
						"~/.local/pipx", "~/.pyenv", "~/.virtualenvs",
						"~/.cache/pypoetry", "~/.config/pypoetry", "~/.local/share/pypoetry",
						"~/.cache/pdm", "~/.config/pdm", "~/.local/share/pdm",
						"~/.cache/pre-commit", "~/.cache/mypy", "~/.cache/ruff",
						"~/.conda", "~/miniconda3", "~/miniforge3",
						"~/.cache/hatch", "~/.config/hatch", "~/.local/share/hatch",
						"~/.ipython", "~/.jupyter", "~/.python_history",
					},
				},
			}
		},
	})
}
