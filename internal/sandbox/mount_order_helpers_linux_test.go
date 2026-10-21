//go:build linux

// Copied verbatim from #103 (greyproxy_denyread_linux_test.go) so this test
// compiles on main. Delete this file when #103 merges.

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedGreyproxyDirIn creates a fake greyproxy data dir at <parent>/greyproxy,
// populated with the sensitive files plus the public ca-cert, and returns the
// data dir path.
func seedGreyproxyDirIn(t *testing.T, parent string) string {
	t.Helper()
	dataDir := filepath.Join(parent, "greyproxy")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	for _, f := range []string{"session.key", "ca-key.pem", "ca-cert.pem", "greyproxy.db"} {
		if err := os.WriteFile(filepath.Join(dataDir, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	return dataDir
}

// bwrapMount is a parsed filesystem-mount argument from the generated command.
type bwrapMount struct {
	flag string // --tmpfs / --ro-bind / --bind / --dev-bind
	src  string // "" for --tmpfs
	dest string
}

// parseBwrapMounts extracts the mount args (in order) from a generated command,
// ignoring everything after the "--" separator (the inner script). Assumes the
// seeded paths have no spaces (t.TempDir on Linux) so Fields recovers tokens.
func parseBwrapMounts(cmd string) []bwrapMount {
	if i := strings.Index(cmd, " -- "); i >= 0 {
		cmd = cmd[:i]
	}
	toks := strings.Fields(cmd)
	var mounts []bwrapMount
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "--tmpfs":
			if i+1 < len(toks) {
				mounts = append(mounts, bwrapMount{flag: toks[i], dest: toks[i+1]})
				i++
			}
		case "--ro-bind", "--ro-bind-try", "--bind", "--bind-try", "--dev-bind":
			if i+2 < len(toks) {
				mounts = append(mounts, bwrapMount{flag: toks[i], src: toks[i+1], dest: toks[i+2]})
				i += 2
			}
		}
	}
	return mounts
}
