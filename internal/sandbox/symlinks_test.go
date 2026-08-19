package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustResolve resolves symlinks in a path (t.TempDir may itself sit behind a
// symlink, e.g. /tmp or /var on macOS).
func mustResolve(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestResolveSymlinkEntry(t *testing.T) {
	tmp := mustResolve(t, t.TempDir())
	target := filepath.Join(tmp, "target.txt")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(tmp, "dangling")
	if err := os.Symlink(filepath.Join(tmp, "missing"), dangling); err != nil {
		t.Fatal(err)
	}

	if _, ok := resolveSymlinkEntry(target); ok {
		t.Error("regular file must not resolve as symlink entry")
	}
	if _, ok := resolveSymlinkEntry(dangling); ok {
		t.Error("dangling symlink must not resolve")
	}
	entry, ok := resolveSymlinkEntry(link)
	if !ok {
		t.Fatal("symlink did not resolve")
	}
	if entry.Link != link || entry.LinkDest != target || entry.Target != target {
		t.Errorf("unexpected entry: %+v", entry)
	}
}

func TestScanEscapingSymlinks(t *testing.T) {
	tmp := mustResolve(t, t.TempDir())
	outside := filepath.Join(tmp, "outside.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(tmp, "allowed")
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	internal := filepath.Join(dir, "internal.txt")
	if err := os.WriteFile(internal, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Internal link (target inside dir), escaping link at top level,
	// escaping link in a subdirectory, dangling link.
	if err := os.Symlink(internal, filepath.Join(dir, "internal-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape-top")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sub, "escape-deep")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tmp, "missing"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}

	targets := func(entries []SymlinkEntry) []string {
		var out []string
		for _, e := range entries {
			out = append(out, e.Link+"->"+e.Target)
		}
		return out
	}

	shallow := scanEscapingSymlinks(dir, false, false)
	if len(shallow) != 1 {
		t.Fatalf("shallow scan: want 1 escaping link, got %v", targets(shallow))
	}
	if shallow[0].Link != filepath.Join(dir, "escape-top") || shallow[0].Target != outside {
		t.Errorf("shallow scan: unexpected entry %+v", shallow[0])
	}

	deep := scanEscapingSymlinks(dir, true, false)
	if len(deep) != 2 {
		t.Fatalf("deep scan: want 2 escaping links, got %v", targets(deep))
	}
	found := false
	for _, e := range deep {
		if e.Link == filepath.Join(sub, "escape-deep") && e.Target == outside {
			found = true
		}
	}
	if !found {
		t.Errorf("deep scan: missing nested escaping link, got %v", targets(deep))
	}
}

func TestExpandPathKeepsSymlinks(t *testing.T) {
	tmp := mustResolve(t, t.TempDir())
	target := filepath.Join(tmp, "target")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if got := ExpandPath(link); got != link {
		t.Errorf("ExpandPath(%q) = %q, must not resolve symlinks", link, got)
	}
	if got := NormalizePath(link); got != target {
		t.Errorf("NormalizePath(%q) = %q, want resolved %q", link, got, target)
	}

	home, _ := os.UserHomeDir()
	if got := ExpandPath("~"); got != home {
		t.Errorf("ExpandPath(~) = %q, want %q", got, home)
	}
}

func TestEscapingSymlinkReadRules(t *testing.T) {
	tmp := mustResolve(t, t.TempDir())
	outside := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tmp, "allowed")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	rules := strings.Join(escapingSymlinkReadRules(dir, "shallow"), "\n")
	want := "(literal " + escapePath(outside) + "))"
	if !strings.Contains(rules, want) {
		t.Errorf("shallow rules missing target literal %q:\n%s", want, rules)
	}

	if rules := escapingSymlinkReadRules(dir, "off"); rules != nil {
		t.Errorf("mode off must produce no rules, got %v", rules)
	}
}

func TestGenerateReadRulesSymlinkedAllowPath(t *testing.T) {
	tmp := mustResolve(t, t.TempDir())
	targetDir := filepath.Join(tmp, "real-config")
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "linked-config")
	if err := os.Symlink(targetDir, link); err != nil {
		t.Fatal(err)
	}

	rules := strings.Join(generateReadRules(true, tmp, []string{link}, nil, nil, "TAG", "shallow"), "\n")
	want := "(subpath " + escapePath(targetDir) + "))"
	if !strings.Contains(rules, want) {
		t.Errorf("read rules missing resolved subpath %q:\n%s", want, rules)
	}
}

func TestScanSkipsSensitiveTargets(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory")
	}
	tmp := mustResolve(t, t.TempDir())
	dir := filepath.Join(tmp, "allowed")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(home, ".ssh")
	if _, err := os.Stat(sshDir); err != nil {
		t.Skipf("no %s on this system", sshDir)
	}
	if err := os.Symlink(sshDir, filepath.Join(dir, "ssh-link")); err != nil {
		t.Fatal(err)
	}
	envTarget := filepath.Join(tmp, ".env")
	if err := os.WriteFile(envTarget, []byte("SECRET=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(envTarget, filepath.Join(dir, "env-link")); err != nil {
		t.Fatal(err)
	}

	for _, e := range scanEscapingSymlinks(dir, true, false) {
		t.Errorf("sensitive target must not be exposed: %s -> %s", e.Link, e.Target)
	}
}
