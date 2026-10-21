//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// A denyWrite of a directory binds the real directory read-only. When that bind
// came after the denyRead masks, it re-exposed every masked file inside it.
func TestWrapCommandLinux_DenyWriteDirectoryDoesNotUnmaskDenyReadFile(t *testing.T) {
	cases := []struct {
		name     string
		denyRead []string
	}{
		{"glob", []string{"~/.ssh/id_*"}},
		{"literal", []string{"~/.ssh/id_ed25519"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			sshDir := filepath.Join(home, ".ssh")
			if err := os.MkdirAll(sshDir, 0o700); err != nil {
				t.Fatal(err)
			}
			privateKey := filepath.Join(sshDir, "id_ed25519")
			if err := os.WriteFile(privateKey, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{Filesystem: config.FilesystemConfig{
				DenyRead:  tc.denyRead,
				DenyWrite: []string{"~/.ssh"},
			}}

			cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true})
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}
			mounts := parseBwrapMounts(cmd)

			maskIndex := lastDestIndex(mounts, privateKey)
			if maskIndex < 0 || mounts[maskIndex].src != "/dev/null" {
				t.Fatalf("private key is not masked with /dev/null; mounts=%+v", mounts)
			}
			if dirIndex := lastDestIndex(mounts, sshDir); dirIndex > maskIndex {
				t.Errorf("~/.ssh is bound at %d, after the private key mask at %d: it re-exposes the key; mounts=%+v", dirIndex, maskIndex, mounts)
			}
		})
	}
}

// A denyRead directory that is also a denyWrite directory must end up hidden,
// not bound read-only.
func TestWrapCommandLinux_DenyReadDirectoryWinsOverDenyWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	privateDir := filepath.Join(home, ".config", "private")
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Filesystem: config.FilesystemConfig{
		DenyRead:  []string{"~/.config/private"},
		DenyWrite: []string{"~/.config/private"},
	}}

	cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	mounts := parseBwrapMounts(cmd)

	i := lastDestIndex(mounts, privateDir)
	if i < 0 || mounts[i].flag != "--tmpfs" {
		t.Errorf("last mount at %q should be the --tmpfs mask; mounts=%+v", privateDir, mounts)
	}
}
