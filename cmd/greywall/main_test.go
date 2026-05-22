// Package main implements the greywall CLI.
package main

import "testing"

// TestProxyIdentity is the regression test for #96. The greyproxy session
// container name and the SOCKS5 login are both derived from proxyIdentity, so
// they can never diverge. Before the fix, the container name was derived
// independently as `cmdName || "sandbox"` and ignored --proxy-user, so a run
// with --proxy-user registered its --allow / profile rules under a container
// name that no live connection ever logged in as, and the rules were silently
// dropped. The "flag overrides command name" case below pins the behavior the
// old container-name derivation got wrong (it would have returned "curl").
func TestProxyIdentity(t *testing.T) {
	tests := []struct {
		name          string
		proxyUserFlag string
		cmdName       string
		want          string
	}{
		{"flag overrides command name", "agent1", "curl", "agent1"},
		{"flag overrides empty command", "agent1", "", "agent1"},
		{"command name when no flag", "", "curl", "curl"},
		{"fallback when both empty", "", "", "proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxyIdentity(tt.proxyUserFlag, tt.cmdName); got != tt.want {
				t.Errorf("proxyIdentity(%q, %q) = %q, want %q",
					tt.proxyUserFlag, tt.cmdName, got, tt.want)
			}
		})
	}
}
