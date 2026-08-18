//go:build linux

package sandbox

import (
	"errors"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func TestNetworkEnforcementErrorRequiresNamespace(t *testing.T) {
	cases := []struct {
		name      string
		unshare   bool
		watch     bool
		wantError bool
	}{
		{name: "namespace available", unshare: true, watch: false, wantError: false},
		{name: "no namespace refuses to run", unshare: false, watch: false, wantError: true},
		{name: "watch mode is exempt", unshare: false, watch: true, wantError: false},
		{name: "watch mode with namespace", unshare: true, watch: true, wantError: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := networkEnforcementError(&LinuxFeatures{CanUnshareNet: tc.unshare}, tc.watch)
			if tc.wantError && err == nil {
				t.Fatal("expected refusal, got nil")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantError && !errors.Is(err, ErrNetworkNotIsolated) {
				t.Errorf("error does not wrap ErrNetworkNotIsolated: %v", err)
			}
		})
	}
}

// TestNetworkEnforcementErrorIsActionable guards the message a user actually
// sees. Refusing to run is only defensible if it says why and what to do.
func TestNetworkEnforcementErrorIsActionable(t *testing.T) {
	err := networkEnforcementError(&LinuxFeatures{CanUnshareNet: false}, false)
	if err == nil {
		t.Fatal("expected refusal")
	}
	for _, want := range []string{"CAP_NET_ADMIN", "--linux-features"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message is missing %q:\n%s", want, err.Error())
		}
	}
}

// TestWrapCommandRefusesWithoutNamespace exercises the whole wrap path in an
// environment the test host cannot itself reproduce, by replacing the feature
// detection seam. Without this the fatal branch would ship untested.
func TestWrapCommandRefusesWithoutNamespace(t *testing.T) {
	original := detectFeatures
	t.Cleanup(func() { detectFeatures = original })
	detectFeatures = func() *LinuxFeatures {
		return &LinuxFeatures{HasBwrap: true, HasSocat: true, CanUnshareNet: false}
	}

	cfg := config.Default()
	_, err := WrapCommandLinuxWithOptions(cfg, "echo hello", nil, nil, nil, nil, nil, "",
		LinuxSandboxOptions{})
	if !errors.Is(err, ErrNetworkNotIsolated) {
		t.Fatalf("expected ErrNetworkNotIsolated, got %v", err)
	}
}

func TestWrapCommandAllowsWatchWithoutNamespace(t *testing.T) {
	original := detectFeatures
	t.Cleanup(func() { detectFeatures = original })
	detectFeatures = func() *LinuxFeatures {
		return &LinuxFeatures{HasBwrap: true, HasSocat: true, CanUnshareNet: false}
	}

	cfg := config.Default()
	_, err := WrapCommandLinuxWithOptions(cfg, "echo hello", nil, nil, nil, nil, nil, "",
		LinuxSandboxOptions{Watch: true})
	if errors.Is(err, ErrNetworkNotIsolated) {
		t.Fatal("watch mode must not be refused for lack of a network namespace")
	}
}
