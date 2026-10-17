//go:build linux

package sandbox

import (
	"errors"
	"os/exec"
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

// requireWrapTools skips when the host cannot run the wrap path at all, so a
// missing tool is not mistaken for the behaviour under test.
func requireWrapTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bwrap", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
}

// withoutNamespace replaces the feature detection seam with an environment
// that cannot create a network namespace.
func withoutNamespace(t *testing.T) {
	t.Helper()
	original := detectFeatures
	t.Cleanup(func() { detectFeatures = original })
	detectFeatures = func() *LinuxFeatures {
		return &LinuxFeatures{HasBwrap: true, HasSocat: true, CanUnshareNet: false}
	}
}

// TestWrapCommandRefusesWithoutNamespace exercises the whole wrap path in an
// environment the test host cannot itself reproduce, by replacing the feature
// detection seam. Without this the fatal branch would ship untested.
func TestWrapCommandRefusesWithoutNamespace(t *testing.T) {
	requireWrapTools(t)
	withoutNamespace(t)

	cfg := config.Default()
	_, err := WrapCommandLinuxWithOptions(cfg, "echo hello", nil, nil, nil, nil, nil, "",
		LinuxSandboxOptions{})
	if !errors.Is(err, ErrNetworkNotIsolated) {
		t.Fatalf("expected ErrNetworkNotIsolated, got %v", err)
	}
}

func TestWrapCommandAllowsWatchWithoutNamespace(t *testing.T) {
	requireWrapTools(t)
	withoutNamespace(t)

	cfg := config.Default()
	wrapped, err := WrapCommandLinuxWithOptions(cfg, "echo hello", nil, nil, nil, nil, nil, "",
		LinuxSandboxOptions{Watch: true})
	if err != nil {
		t.Fatalf("watch mode must run without a network namespace, got %v", err)
	}
	if strings.Contains(wrapped, "--unshare-net") {
		t.Error("watch mode without a namespace must not request --unshare-net")
	}
}

// TestManagerRefusesBeforeStartingBridges checks that the refusal happens in
// Initialize, before any bridge process, socket or temp file is created.
func TestManagerRefusesBeforeStartingBridges(t *testing.T) {
	withoutNamespace(t)

	cfg := config.Default()
	cfg.Network.ProxyURL = "socks5://127.0.0.1:1"
	cfg.Network.HTTPProxyURL = "http://127.0.0.1:2"
	cfg.Network.DnsAddr = "127.0.0.1:3"
	m := NewManager(cfg, false, false)
	t.Cleanup(m.Cleanup)

	if err := m.Initialize(); !errors.Is(err, ErrNetworkNotIsolated) {
		t.Fatalf("expected ErrNetworkNotIsolated, got %v", err)
	}
	if m.proxyBridge != nil || m.httpProxyBridge != nil || m.dnsBridge != nil || m.tun2socksPath != "" {
		t.Error("refusal must happen before any bridge or tun2socks binary is created")
	}
}

func TestSandboxProxyEnv(t *testing.T) {
	socks := &ProxyBridge{Scheme: "socks5", HasAuth: true, ProxyUser: "opencode", ProxyPass: "proxy"}
	httpBridge := &ProxyBridge{Scheme: "http", HasAuth: true, ProxyUser: "opencode", ProxyPass: "proxy"}
	const (
		socksURL = "socks5h://opencode:proxy@127.0.0.1:18321"
		httpURL  = "http://opencode:proxy@127.0.0.1:18322" //nolint:gosec // proxy identity, not a secret
	)

	cases := []struct {
		name        string
		http        *ProxyBridge
		transparent bool
		wantHTTP    string // "" = HTTP(S)_PROXY must be unset
	}{
		{name: "http bridge with TUN", http: httpBridge, transparent: true, wantHTTP: httpURL},
		{name: "http bridge without TUN", http: httpBridge, transparent: false, wantHTTP: httpURL},
		{name: "no http bridge, TUN carries non-SOCKS clients", transparent: true, wantHTTP: ""},
		{name: "no http bridge, no TUN", transparent: false, wantHTTP: socksURL},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for _, kv := range sandboxProxyEnv(socks, tc.http, tc.transparent) {
				env[kv[0]] = kv[1]
			}
			for _, k := range []string{"ALL_PROXY", "all_proxy"} {
				if env[k] != socksURL {
					t.Errorf("%s = %q, want %q", k, env[k], socksURL)
				}
			}
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				got, ok := env[k]
				if tc.wantHTTP == "" {
					if ok {
						t.Errorf("%s = %q, want unset", k, got)
					}
					continue
				}
				if got != tc.wantHTTP {
					t.Errorf("%s = %q, want %q", k, got, tc.wantHTTP)
				}
			}
			if env["NO_PROXY"] != "localhost,127.0.0.1" {
				t.Errorf("NO_PROXY = %q", env["NO_PROXY"])
			}
		})
	}
}

func TestSandboxProxyEnvWithoutCredentials(t *testing.T) {
	env := sandboxProxyEnv(&ProxyBridge{Scheme: "socks5"}, nil, false)
	if env[0][1] != "socks5h://127.0.0.1:18321" {
		t.Errorf("ALL_PROXY = %q, want no userinfo", env[0][1])
	}
}
