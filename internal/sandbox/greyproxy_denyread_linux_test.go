//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// seedGreyproxyDir creates a fake greyproxy data dir under a temp HOME and
// returns (home, dataDir). It sets HOME + clears XDG_DATA_HOME so the sandbox
// path helpers resolve to this dir.
func seedGreyproxyDir(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "") // use the default ~/.local/share path

	dataDir := filepath.Join(home, ".local", "share", "greyproxy")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	for _, f := range []string{"session.key", "ca-key.pem", "ca-cert.pem", "greyproxy.db"} {
		if err := os.WriteFile(filepath.Join(dataDir, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	return home, dataDir
}

// TestGreyproxyDenyReadArgs is a focused regression test for the
// credential-protection defect where greyproxy's session key, CA private key
// and encrypted store were left READABLE inside the Linux sandbox.
//
// Root cause: the greyproxy secrets were routed through getMandatoryDenyPaths(),
// which emits the deny-WRITE idiom (--ro-bind realfile realfile). That keeps a
// path read-only but still readable, and — being emitted after the denyRead
// /dev/null mask — clobbered it. Separately, the generic ~/.local home-cache
// bind wholesale-exposed the greyproxy data directory (including greyproxy.db).
func TestGreyproxyDenyReadArgs(t *testing.T) {
	_, dataDir := seedGreyproxyDir(t)
	sessionKey := filepath.Join(dataDir, "session.key")
	caKey := filepath.Join(dataDir, "ca-key.pem")
	caCert := filepath.Join(dataDir, "ca-cert.pem")
	db := filepath.Join(dataDir, "greyproxy.db")

	args := greyproxyDenyReadArgs()

	tmpfsIdx := indexOfPair(args, "--tmpfs", dataDir)
	if tmpfsIdx < 0 {
		t.Errorf("expected --tmpfs mask of greyproxy data dir %q; args=%v", dataDir, args)
	}
	for _, secret := range []string{sessionKey, caKey} {
		if indexOfTriple(args, "--ro-bind", "/dev/null", secret) < 0 {
			t.Errorf("expected %q to be masked with /dev/null; args=%v", secret, args)
		}
		if indexOfTriple(args, "--ro-bind", secret, secret) >= 0 {
			t.Errorf("secret %q is re-exposed read-only as the real file; args=%v", secret, args)
		}
	}
	certIdx := indexOfTriple(args, "--ro-bind", caCert, caCert)
	if certIdx < 0 {
		t.Fatalf("expected ca-cert.pem to be re-exposed read-only; args=%v", args)
	}
	if tmpfsIdx >= 0 && certIdx < tmpfsIdx {
		t.Errorf("ca-cert re-bind (%d) must come after the data-dir tmpfs mask (%d) to win", certIdx, tmpfsIdx)
	}
	if indexOfTriple(args, "--ro-bind", db, db) >= 0 {
		t.Errorf("greyproxy.db is re-exposed read-only; args=%v", args)
	}
}

// TestGetMandatoryDenyPathsExcludesGreyproxySecrets asserts the greyproxy
// secrets are NOT routed through the deny-WRITE mandatory path (which would
// re-expose them readable).
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

// TestWrapCommandLinux_GreyproxySecretsMaskedIncludingWatch is the real
// integration assertion: it drives the FULL wrapper (WrapCommandLinuxWithOptions)
// in BOTH the enforcing path and --watch mode, with a greyproxy data dir present
// (i.e. credential substitution active), and verifies against the complete
// generated bwrap command that:
//
//   - the data dir is masked with an empty tmpfs and the key files with
//     /dev/null;
//   - NO later bind re-exposes session.key / ca-key.pem / greyproxy.db (neither
//     a real-file ro-bind nor an ancestor bind emitted after the mask);
//   - ca-cert.pem stays readable.
//
// It would fail if the mask helper is skipped (the --watch bypass bug) or
// appended before a clobbering bind — the two ways the isolated helper test
// could be defeated.
func TestWrapCommandLinux_GreyproxySecretsMaskedIncludingWatch(t *testing.T) {
	modes := []struct {
		name string
		opts LinuxSandboxOptions
	}{
		{"enforcing", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true}},
		{"watch", LinuxSandboxOptions{Watch: true}},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			home, dataDir := seedGreyproxyDir(t)
			// Deny-by-default (DefaultDenyRead nil => true) exercises the
			// ~/.local home-cache bind that originally clobbered the mask.
			cfg := &config.Config{Filesystem: config.FilesystemConfig{}}

			cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", m.opts)
			if err != nil {
				t.Fatalf("[%s] wrap failed: %v", m.name, err)
			}

			sk := filepath.Join(dataDir, "session.key")
			ck := filepath.Join(dataDir, "ca-key.pem")
			cc := filepath.Join(dataDir, "ca-cert.pem")
			db := filepath.Join(dataDir, "greyproxy.db")

			tmpfsMask := "--tmpfs " + dataDir
			maskAt := strings.LastIndex(cmd, tmpfsMask)
			if maskAt < 0 {
				t.Fatalf("[%s] greyproxy data dir not masked with tmpfs; the mask is not applied in this mode", m.name)
			}

			// Key files masked with /dev/null, never re-exposed as real files.
			for _, p := range []string{sk, ck} {
				if !strings.Contains(cmd, "--ro-bind /dev/null "+p) {
					t.Errorf("[%s] %q not masked with /dev/null", m.name, p)
				}
			}
			for _, p := range []string{sk, ck, db} {
				if strings.Contains(cmd, "--ro-bind "+p+" "+p) {
					t.Errorf("[%s] secret %q re-exposed as the real file", m.name, p)
				}
			}

			// ca-cert.pem stays readable, and its re-bind wins over the mask.
			ccReBind := "--ro-bind " + cc + " " + cc
			ccAt := strings.LastIndex(cmd, ccReBind)
			if ccAt < 0 {
				t.Errorf("[%s] ca-cert.pem not re-exposed read-only (TLS trust broken)", m.name)
			} else if ccAt < maskAt {
				t.Errorf("[%s] ca-cert re-bind (%d) must come after the dir mask (%d)", m.name, ccAt, maskAt)
			}

			// Nothing may re-expose the secrets AFTER the mask: assert every
			// bind of an ancestor directory of the greyproxy dir is emitted
			// BEFORE the mask (so "last mount wins" keeps the mask in effect).
			ancestors := []string{
				"--bind " + home + " " + home,                                                      // watch: writable home
				"--ro-bind " + home + " " + home,                                                   // legacy home ro-bind
				"--ro-bind " + filepath.Join(home, ".local") + " " + filepath.Join(home, ".local"), // deny-default home cache
			}
			for _, anc := range ancestors {
				if i := strings.LastIndex(cmd, anc); i >= 0 && i > maskAt {
					t.Errorf("[%s] ancestor bind %q at %d re-exposes greyproxy secrets AFTER the mask at %d", m.name, anc, i, maskAt)
				}
			}
		})
	}
}

// indexOfPair returns the index of a two-token mount arg (flag, dest), or -1.
func indexOfPair(args []string, flag, dest string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == dest {
			return i
		}
	}
	return -1
}

// indexOfTriple returns the index of a three-token mount arg (flag, src, dest),
// or -1.
func indexOfTriple(args []string, flag, src, dest string) int {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == flag && args[i+1] == src && args[i+2] == dest {
			return i
		}
	}
	return -1
}
