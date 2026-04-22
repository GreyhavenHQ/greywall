package profiles

import (
	"fmt"
	"sort"
	"strings"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// DiffConfigs returns a human-readable additions-only diff of the slice-valued
// fields that matter for drift resolution (network rules, filesystem paths,
// command lists, SSH entries, credentials). Scalar fields are intentionally
// omitted; they are rarely the source of drift and noisy to render.
//
// Only entries present in `after` but not `before` are shown (`+`). Removals
// are intentionally hidden: drift resolution is additive so users never lose
// their customizations.
//
// If there are no additions, returns an empty string.
func DiffConfigs(before, after *config.Config) string {
	if before == nil {
		before = &config.Config{}
	}
	if after == nil {
		after = &config.Config{}
	}

	var sections []string

	add := func(label string, beforeItems, afterItems []string) {
		added := setAdditions(beforeItems, afterItems)
		if len(added) == 0 {
			return
		}
		var b strings.Builder
		fmt.Fprintf(&b, "  %s\n", label)
		for _, s := range added {
			fmt.Fprintf(&b, "    + %s\n", s)
		}
		sections = append(sections, b.String())
	}

	add("network.rules", formatRules(before.Network.Rules), formatRules(after.Network.Rules))
	add("network.allowUnixSockets", before.Network.AllowUnixSockets, after.Network.AllowUnixSockets)
	add("network.forwardPorts", formatInts(before.Network.ForwardPorts), formatInts(after.Network.ForwardPorts))

	add("filesystem.allowRead", before.Filesystem.AllowRead, after.Filesystem.AllowRead)
	add("filesystem.denyRead", before.Filesystem.DenyRead, after.Filesystem.DenyRead)
	add("filesystem.allowWrite", before.Filesystem.AllowWrite, after.Filesystem.AllowWrite)
	add("filesystem.denyWrite", before.Filesystem.DenyWrite, after.Filesystem.DenyWrite)

	add("command.deny", before.Command.Deny, after.Command.Deny)
	add("command.allow", before.Command.Allow, after.Command.Allow)

	add("ssh.allowedHosts", before.SSH.AllowedHosts, after.SSH.AllowedHosts)
	add("ssh.deniedHosts", before.SSH.DeniedHosts, after.SSH.DeniedHosts)
	add("ssh.allowedCommands", before.SSH.AllowedCommands, after.SSH.AllowedCommands)
	add("ssh.deniedCommands", before.SSH.DeniedCommands, after.SSH.DeniedCommands)

	add("credentials.secrets", before.Credentials.Secrets, after.Credentials.Secrets)
	add("credentials.inject", before.Credentials.Inject, after.Credentials.Inject)
	add("credentials.ignore", before.Credentials.Ignore, after.Credentials.Ignore)

	return strings.Join(sections, "")
}

// setAdditions returns entries present in `after` but not in `before`, sorted.
func setAdditions(before, after []string) []string {
	beforeSet := make(map[string]struct{}, len(before))
	for _, s := range before {
		beforeSet[s] = struct{}{}
	}
	var added []string
	for _, s := range after {
		if _, ok := beforeSet[s]; !ok {
			added = append(added, s)
		}
	}
	// Dedupe in case `after` has duplicates.
	sort.Strings(added)
	out := added[:0]
	var prev string
	for i, s := range added {
		if i == 0 || s != prev {
			out = append(out, s)
		}
		prev = s
	}
	return out
}

// formatRules renders network rules as "destination:port action" strings so
// they diff meaningfully as set members.
func formatRules(rules []config.NetworkRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		port := r.Port
		if port == "" {
			port = "*"
		}
		action := r.Action
		if action == "" {
			action = "allow"
		}
		out = append(out, fmt.Sprintf("%s:%s %s", r.Destination, port, action))
	}
	return out
}

func formatInts(xs []int) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, fmt.Sprintf("%d", x))
	}
	return out
}
