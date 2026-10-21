//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// bubblewrap applies mounts in order and the last mount on a path wins. A mount
// emitted after a denyRead mask, on the masked path or on one of its parents,
// replaces the mask with the real files. This test builds the bwrap command for
// many configurations and fails on any such mount, whatever code emitted it.
func TestWrapCommandLinux_NoMountCoversDenyReadMask(t *testing.T) {
	cases := []struct {
		name string
		// fs returns the filesystem config under test.
		fs func(home, cwd string) config.FilesystemConfig
		// masked returns the paths that must end up hidden.
		masked func(home, cwd string) []string
		// greyproxy seeds a greyproxy data dir, whose secrets are always masked.
		greyproxy bool
	}{
		{
			name: "denyRead file",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{DenyRead: []string{"~/secret.txt"}}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, "secret.txt")}
			},
		},
		{
			name: "denyRead folder",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{DenyRead: []string{"~/.aws"}}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, ".aws")}
			},
		},
		{
			name: "denyRead glob",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{DenyRead: []string{"~/.ssh/id_*"}}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, ".ssh", "id_ed25519")}
			},
		},
		{
			name: "denyWrite on the parent of a denyRead glob",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:  []string{"~/.ssh/id_*"},
					DenyWrite: []string{"~/.ssh"},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, ".ssh", "id_ed25519")}
			},
		},
		{
			name: "denyWrite on the parent of a denyRead file",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:  []string{"~/.ssh/id_ed25519"},
					DenyWrite: []string{"~/.ssh"},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, ".ssh", "id_ed25519")}
			},
		},
		{
			name: "denyWrite on the same folder as denyRead",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:  []string{"~/.aws"},
					DenyWrite: []string{"~/.aws"},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, ".aws")}
			},
		},
		{
			name: "denyWrite glob matching a denyRead file",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:  []string{"~/.ssh/id_ed25519"},
					DenyWrite: []string{"~/.ssh/*"},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, ".ssh", "id_ed25519")}
			},
		},
		{
			name: "allowWrite on the parent of a denyRead folder",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:   []string{"~/work/.secrets"},
					AllowWrite: []string{"~/work"},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, "work", ".secrets")}
			},
		},
		{
			name: "allowWrite on the same path as denyRead",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:   []string{"~/work/.secrets"},
					AllowWrite: []string{"~/work/.secrets"},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, "work", ".secrets")}
			},
		},
		{
			name: "allowWrite on the working directory",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:   []string{filepath.Join(cwd, "private.key")},
					AllowWrite: []string{"."},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(cwd, "private.key")}
			},
		},
		{
			name: "denyWrite on the working directory",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					DenyRead:  []string{filepath.Join(cwd, "private.key")},
					DenyWrite: []string{"."},
				}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(cwd, "private.key")}
			},
		},
		{
			name: "denyRead on mandatory deny paths in home",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{DenyRead: []string{"~/.bashrc", "~/.gitconfig"}}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(home, ".bashrc"), filepath.Join(home, ".gitconfig")}
			},
		},
		{
			name: "denyRead on mandatory deny paths in the working directory",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{DenyRead: []string{
					filepath.Join(cwd, ".git", "hooks"),
					filepath.Join(cwd, ".git", "config"),
					filepath.Join(cwd, ".vscode"),
				}}
			},
			masked: func(home, cwd string) []string {
				return []string{
					filepath.Join(cwd, ".git", "hooks"),
					filepath.Join(cwd, ".git", "config"),
					filepath.Join(cwd, ".vscode"),
				}
			},
		},
		{
			name: "denyRead on the parent of mandatory deny paths",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{DenyRead: []string{filepath.Join(cwd, ".git")}}
			},
			masked: func(home, cwd string) []string {
				return []string{filepath.Join(cwd, ".git")}
			},
		},
		{
			name: "greyproxy data dir",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{}
			},
			masked:    func(home, cwd string) []string { return nil },
			greyproxy: true,
		},
		{
			name: "greyproxy data dir under allowWrite and denyWrite parents",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{
					AllowWrite: []string{"~/.local/share"},
					DenyWrite:  []string{"~/.local"},
				}
			},
			masked:    func(home, cwd string) []string { return nil },
			greyproxy: true,
		},
		{
			name: "greyproxy data dir also in denyRead",
			fs: func(home, cwd string) config.FilesystemConfig {
				return config.FilesystemConfig{DenyRead: []string{
					"~/.local/share/greyproxy",
					"~/.local/share/greyproxy/session.key",
				}}
			},
			masked:    func(home, cwd string) []string { return nil },
			greyproxy: true,
		},
	}

	for _, defaultDenyRead := range []bool{false, true} {
		for _, tc := range cases {
			name := tc.name + "/defaultDenyRead=false"
			if defaultDenyRead {
				name = tc.name + "/defaultDenyRead=true"
			}
			t.Run(name, func(t *testing.T) {
				home, cwd := seedMountOrderTree(t)
				fs := tc.fs(home, cwd)
				fs.DefaultDenyRead = &defaultDenyRead
				cfg := &config.Config{Filesystem: fs}

				masked := tc.masked(home, cwd)
				if tc.greyproxy {
					dataDir := seedGreyproxyDirIn(t, filepath.Join(home, ".local", "share"))
					masked = append(
						masked,
						dataDir,
						filepath.Join(dataDir, "session.key"),
						filepath.Join(dataDir, "ca-key.pem"),
					)
				}
				if defaultDenyRead {
					// Deny-by-default masks sensitive project files on its own.
					masked = append(masked, filepath.Join(cwd, ".env"))
				}

				cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true})
				if err != nil {
					t.Fatalf("wrap: %v", err)
				}
				assertNoMountCoversMask(t, parseBwrapMounts(cmd), masked)
			})
		}
	}
}

// assertNoMountCoversMask fails when a path in masked has no mask, or when a
// bind after its last mask targets the path itself or one of its parents.
func assertNoMountCoversMask(t *testing.T, mounts []bwrapMount, masked []string) {
	t.Helper()
	for _, path := range masked {
		maskIndex := -1
		for i, mount := range mounts {
			if mount.dest == path && isMaskMount(mount) {
				maskIndex = i
			}
		}
		if maskIndex < 0 {
			t.Errorf("%s is never masked; mounts=%+v", path, mounts)
			continue
		}
		for i := maskIndex + 1; i < len(mounts); i++ {
			// A later mask, like the sandbox's own --tmpfs /tmp, hides even more.
			if isMaskMount(mounts[i]) {
				continue
			}
			if isSameOrParentPath(mounts[i].dest, path) {
				t.Errorf("mount %d (%s %s %s) comes after the mask of %s at %d and re-exposes it; mounts=%+v",
					i, mounts[i].flag, mounts[i].src, mounts[i].dest, path, maskIndex, mounts)
			}
		}
	}
}

// isMaskMount reports whether the mount hides what is under its destination:
// an empty tmpfs, /dev/null, or the empty file deny-by-default uses for .env.
func isMaskMount(mount bwrapMount) bool {
	if mount.flag == "--tmpfs" {
		return true
	}
	if mount.flag != "--ro-bind" {
		return false
	}
	return mount.src == "/dev/null" || mount.src == filepath.Join(os.TempDir(), "greywall", "empty")
}

func isSameOrParentPath(candidate, path string) bool {
	return candidate == path || candidate == "/" || strings.HasPrefix(path, candidate+"/")
}

// seedMountOrderTree creates a fake HOME and working directory holding every
// path the cases refer to, and makes them the test's HOME and cwd.
func seedMountOrderTree(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Chdir(cwd)

	for _, dir := range []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, "work", ".secrets"),
		filepath.Join(cwd, ".git", "hooks"),
		filepath.Join(cwd, ".vscode"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "config"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, "secret.txt"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, "work", ".secrets", "token"),
		filepath.Join(cwd, ".git", "config"),
		filepath.Join(cwd, ".env"),
		filepath.Join(cwd, "private.key"),
	} {
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home, cwd
}
