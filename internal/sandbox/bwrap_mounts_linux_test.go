//go:build linux

package sandbox

import "strings"

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
