//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// seedGreyproxyDirIn creates a fake greyproxy data dir at <parent>/greyproxy,
// populated with the sensitive files plus the public ca-cert, and returns the
// data dir path.
func seedGreyproxyDirIn(t *testing.T, parent string) string {
	t.Helper()
	dataDir := filepath.Join(parent, "greyproxy")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	for _, f := range []string{"session.key", "ca-key.pem", "ca-cert.pem", "greyproxy.db"} {
		if err := os.WriteFile(filepath.Join(dataDir, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	return dataDir
}

// seedGreyproxyDir creates a fake greyproxy data dir under a temp HOME using the
// default (~/.local/share) layout and returns (home, dataDir). It sets HOME and
// clears XDG_DATA_HOME so the sandbox path helpers resolve to this dir.
func seedGreyproxyDir(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "") // use the default ~/.local/share path
	dataDir := seedGreyproxyDirIn(t, filepath.Join(home, ".local", "share"))
	return home, dataDir
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

// lastDestIndex returns the index of the last mount whose dest == path (the one
// in effect under "last mount wins"), or -1.
func lastDestIndex(mounts []bwrapMount, path string) int {
	idx := -1
	for i, m := range mounts {
		if m.dest == path {
			idx = i
		}
	}
	return idx
}

// ancestorsOf returns every proper ancestor directory of path up to "/". A bind
// of any of these landing after the mask would re-expose the subtree.
func ancestorsOf(path string) []string {
	var out []string
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		out = append(out, p)
		if parent := filepath.Dir(p); parent == p {
			break
		}
	}
	return out
}

// assertGreyproxyMaskWins asserts the effective (last-wins) mounts leave the
// data dir a tmpfs, no ancestor re-bound after it, the secret files masked with
// /dev/null, greyproxy.db not re-exposed, and ca-cert.pem readable.
func assertGreyproxyMaskWins(t *testing.T, mounts []bwrapMount, dataDir string) {
	t.Helper()

	maskIdx := lastDestIndex(mounts, dataDir)
	if maskIdx < 0 {
		t.Fatalf("greyproxy data dir %q is never mounted/masked; mounts=%+v", dataDir, mounts)
	}
	if mounts[maskIdx].flag != "--tmpfs" {
		t.Fatalf("last mount at data dir %q is %q (src=%q), want --tmpfs mask — the mask was clobbered; mounts=%+v",
			dataDir, mounts[maskIdx].flag, mounts[maskIdx].src, mounts)
	}

	// No ancestor may be (re-)bound after the mask, whatever the flag or path.
	for _, anc := range ancestorsOf(dataDir) {
		if i := lastDestIndex(mounts, anc); i > maskIdx {
			t.Errorf("ancestor %q is bound at index %d, AFTER the data-dir mask at %d — it re-exposes the greyproxy secrets; mounts=%+v",
				anc, i, maskIdx, mounts)
		}
	}

	// Each secret file's effective mount must be /dev/null, never the real file.
	for _, secret := range []string{
		filepath.Join(dataDir, "session.key"),
		filepath.Join(dataDir, "ca-key.pem"),
	} {
		i := lastDestIndex(mounts, secret)
		if i < 0 {
			t.Errorf("secret %q has no explicit /dev/null mask (defense-in-depth); mounts=%+v", secret, mounts)
			continue
		}
		if mounts[i].src != "/dev/null" {
			t.Errorf("secret %q effective mount is %q from src %q, want --ro-bind /dev/null (real file re-exposed); mounts=%+v",
				secret, mounts[i].flag, mounts[i].src, mounts)
		}
	}

	db := filepath.Join(dataDir, "greyproxy.db")
	if i := lastDestIndex(mounts, db); i >= 0 && mounts[i].src == db {
		t.Errorf("greyproxy.db is re-exposed as the real file at index %d; mounts=%+v", i, mounts)
	}

	// ca-cert.pem must be re-exposed (TLS trust) and win over the tmpfs.
	cc := filepath.Join(dataDir, "ca-cert.pem")
	i := lastDestIndex(mounts, cc)
	if i < 0 || mounts[i].src != cc {
		t.Errorf("ca-cert.pem not re-exposed as the real file (TLS trust broken); mounts=%+v", mounts)
	} else if i < maskIdx {
		t.Errorf("ca-cert re-bind at %d precedes the data-dir mask at %d — it would be wiped by the tmpfs; mounts=%+v", i, maskIdx, mounts)
	}
}

// TestGreyproxyDenyReadArgs unit-tests the helper in isolation. Clobbering by
// other binds is covered by TestWrapCommandLinux_GreyproxySecretsMaskedIncludingWatch.
func TestGreyproxyDenyReadArgs(t *testing.T) {
	_, dataDir := seedGreyproxyDir(t)
	sessionKey := filepath.Join(dataDir, "session.key")
	caKey := filepath.Join(dataDir, "ca-key.pem")
	caCert := filepath.Join(dataDir, "ca-cert.pem")
	db := filepath.Join(dataDir, "greyproxy.db")

	mounts := parseBwrapMounts(strings.Join(greyproxyDenyReadArgs(), " "))

	if i := lastDestIndex(mounts, dataDir); i < 0 || mounts[i].flag != "--tmpfs" {
		t.Errorf("expected --tmpfs mask of greyproxy data dir %q; mounts=%+v", dataDir, mounts)
	}
	for _, secret := range []string{sessionKey, caKey} {
		i := lastDestIndex(mounts, secret)
		if i < 0 || mounts[i].src != "/dev/null" {
			t.Errorf("expected %q masked with /dev/null; mounts=%+v", secret, mounts)
		}
	}
	if i := lastDestIndex(mounts, caCert); i < 0 || mounts[i].src != caCert {
		t.Errorf("expected ca-cert.pem re-exposed read-only; mounts=%+v", mounts)
	}
	if i := lastDestIndex(mounts, db); i >= 0 && mounts[i].src == db {
		t.Errorf("greyproxy.db re-exposed as the real file; mounts=%+v", mounts)
	}
}

// TestGetMandatoryDenyPathsExcludesGreyproxySecrets asserts the secrets aren't
// routed through the deny-WRITE path (which would leave them readable).
func TestGetMandatoryDenyPathsExcludesGreyproxySecrets(t *testing.T) {
	seedGreyproxyDir(t)

	paths := getMandatoryDenyPaths(t.TempDir())
	for _, secret := range SensitiveGreyproxyFiles() {
		for _, p := range paths {
			if p == secret {
				t.Errorf("greyproxy secret %q must not be in getMandatoryDenyPaths (deny-write re-exposes it readable)", secret)
			}
		}
	}
}

// TestWrapCommandLinux_GreyproxySecretsMaskedIncludingWatch drives the full
// wrapper in enforcing and --watch modes. The hostile cases add a reverse bridge
// whose socket dir is the data dir, emitting a "--bind <data-dir> <data-dir>" in
// the post-mask region — which fails unless the mask is emitted genuinely last.
func TestWrapCommandLinux_GreyproxySecretsMaskedIncludingWatch(t *testing.T) {
	cases := []struct {
		name    string
		opts    LinuxSandboxOptions
		hostile bool // add a reverse bridge whose socket dir == the greyproxy data dir
	}{
		{"enforcing", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true}, false},
		{"watch", LinuxSandboxOptions{Watch: true}, false},
		{"enforcing_hostile_reverse_bridge", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true}, true},
		{"watch_hostile_reverse_bridge", LinuxSandboxOptions{Watch: true}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dataDir := seedGreyproxyDir(t)
			// Deny-by-default exercises the ~/.local home-cache bind that
			// originally clobbered the mask.
			cfg := &config.Config{Filesystem: config.FilesystemConfig{}}

			var reverseBridge *ReverseBridge
			if tc.hostile {
				// Nil Ports skips the socat loop; the socket-dir bind still fires.
				reverseBridge = &ReverseBridge{SocketPaths: []string{filepath.Join(dataDir, "rev.sock")}}
			}

			cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, reverseBridge, nil, nil, "", tc.opts)
			if err != nil {
				t.Fatalf("[%s] wrap failed: %v", tc.name, err)
			}
			mounts := parseBwrapMounts(cmd)

			assertGreyproxyMaskWins(t, mounts, dataDir)

			if tc.hostile {
				// Sanity: confirm the hostile --bind is actually present (before
				// the mask), so the test can't pass vacuously.
				maskIdx := lastDestIndex(mounts, dataDir)
				found := false
				for i, m := range mounts {
					if i < maskIdx && m.dest == dataDir && (m.flag == "--bind" || m.flag == "--ro-bind") && m.src == dataDir {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("[%s] expected a hostile --bind %s %s before the mask; mounts=%+v", tc.name, dataDir, dataDir, mounts)
				}
			}
		})
	}
}

// TestWrapCommandLinux_GreyproxyMaskWithXDGDataHome guards the XDG_DATA_HOME
// relocation: the store must still be masked when it lives at $XDG_DATA_HOME.
func TestWrapCommandLinux_GreyproxyMaskWithXDGDataHome(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", xdg)

	dataDir := seedGreyproxyDirIn(t, xdg)
	cfg := &config.Config{Filesystem: config.FilesystemConfig{}}

	cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true})
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	assertGreyproxyMaskWins(t, parseBwrapMounts(cmd), dataDir)
}

// TestSensitiveGreyproxyPathsHonorXDG asserts both helpers include the
// XDG_DATA_HOME location, so dir and file masks can't diverge.
func TestSensitiveGreyproxyPathsHonorXDG(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", xdg)

	wantDir := filepath.Join(xdg, "greyproxy")
	if !slices.Contains(SensitiveGreyproxyDirs(), wantDir) {
		t.Errorf("SensitiveGreyproxyDirs missing XDG dir %q: %v", wantDir, SensitiveGreyproxyDirs())
	}
	for _, f := range []string{"session.key", "ca-key.pem"} {
		want := filepath.Join(wantDir, f)
		if !slices.Contains(SensitiveGreyproxyFiles(), want) {
			t.Errorf("SensitiveGreyproxyFiles missing XDG secret %q: %v", want, SensitiveGreyproxyFiles())
		}
	}
}

// TestWrapCommandLinux_GreyproxySecretsUnreadableAtRuntime runs real bubblewrap
// and reads each path from inside the sandbox. Seeded files contain "x", so a
// masked path reads empty and a re-exposed one reads "x". Skips when bwrap can't
// create a namespace (e.g. unprivileged CI), per repo convention.
func TestWrapCommandLinux_GreyproxySecretsUnreadableAtRuntime(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")

	_, dataDir := seedGreyproxyDir(t)
	cfg := &config.Config{Filesystem: config.FilesystemConfig{}}

	sk := filepath.Join(dataDir, "session.key")
	ck := filepath.Join(dataDir, "ca-key.pem")
	db := filepath.Join(dataDir, "greyproxy.db")
	cc := filepath.Join(dataDir, "ca-cert.pem")

	// Read each path with a pure-bash redirection ($(<file)) so no external
	// binary is required inside the sandbox. Unreadable/absent -> empty.
	probe := "printf 'sk=[%s]\\n' \"$(<" + sk + ")\"; " +
		"printf 'ck=[%s]\\n' \"$(<" + ck + ")\"; " +
		"printf 'db=[%s]\\n' \"$(<" + db + ")\"; " +
		"printf 'cc=[%s]\\n' \"$(<" + cc + ")\""

	cmd, err := WrapCommandLinuxWithOptions(cfg, probe, nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	out, runErr := exec.Command("bash", "-c", cmd).CombinedOutput()
	got := string(out)

	// If bubblewrap can't stand up a namespace here, skip rather than fail.
	if !strings.Contains(got, "sk=[") {
		if strings.Contains(got, "Creating new namespace failed") ||
			strings.Contains(got, "setting up uid map") ||
			strings.Contains(got, "bwrap:") {
			t.Skipf("skipping: bwrap cannot create a sandbox here: %v\n%s", runErr, got)
		}
		t.Fatalf("sandbox run produced no probe output: %v\n%s", runErr, got)
	}

	for _, masked := range []string{"sk=[]", "ck=[]", "db=[]"} {
		if !strings.Contains(got, masked) {
			t.Errorf("expected %q (greyproxy secret masked at runtime); output:\n%s", masked, got)
		}
	}
	if !strings.Contains(got, "cc=[x]") {
		t.Errorf("expected cc=[x] (public ca-cert readable at runtime); output:\n%s", got)
	}
}
