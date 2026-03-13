package sandbox

import (
	"fmt"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// TestMacOS_NetworkRestrictionWithProxy verifies that when a proxy URL is set,
// the macOS sandbox profile allows outbound to the proxy host:port.
func TestMacOS_NetworkRestrictionWithProxy(t *testing.T) {
	tests := []struct {
		name      string
		proxyURL  string
		wantProxy bool
		proxyHost string
		proxyPort string
	}{
		{
			name:      "no proxy - network blocked",
			proxyURL:  "",
			wantProxy: false,
		},
		{
			name:      "socks5 proxy - outbound allowed to proxy",
			proxyURL:  "socks5://proxy.example.com:1080",
			wantProxy: true,
			proxyHost: "proxy.example.com",
			proxyPort: "1080",
		},
		{
			name:      "socks5h proxy - outbound allowed to proxy",
			proxyURL:  "socks5h://localhost:1080",
			wantProxy: true,
			proxyHost: "localhost",
			proxyPort: "1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Network: config.NetworkConfig{
					ProxyURL: tt.proxyURL,
				},
				Filesystem: config.FilesystemConfig{
					AllowWrite: []string{"/tmp/test"},
				},
			}

			params := buildMacOSParamsForTest(cfg)

			if tt.wantProxy {
				if params.ProxyHost != tt.proxyHost {
					t.Errorf("expected ProxyHost %q, got %q", tt.proxyHost, params.ProxyHost)
				}
				if params.ProxyPort != tt.proxyPort {
					t.Errorf("expected ProxyPort %q, got %q", tt.proxyPort, params.ProxyPort)
				}

				profile := GenerateSandboxProfile(params)
				expectedRule := `(allow network-outbound (remote tcp "` + tt.proxyHost + ":" + tt.proxyPort + `"))`
				if !strings.Contains(profile, expectedRule) {
					t.Errorf("profile should contain proxy outbound rule %q", expectedRule)
				}
			}

			// Network should always be restricted (proxy or not)
			if !params.NeedsNetworkRestriction {
				t.Error("NeedsNetworkRestriction should always be true")
			}
		})
	}
}

// buildMacOSParamsForTest is a helper to build MacOSSandboxParams from config,
// replicating the logic in WrapCommandMacOS for testing.
func buildMacOSParamsForTest(cfg *config.Config) MacOSSandboxParams {
	allowPaths := append(GetDefaultWritePaths(), cfg.Filesystem.AllowWrite...)
	allowLocalBinding := cfg.Network.AllowLocalBinding
	allowLocalOutbound := allowLocalBinding
	if cfg.Network.AllowLocalOutbound != nil {
		allowLocalOutbound = *cfg.Network.AllowLocalOutbound
	}

	var proxyHost, proxyPort string
	if cfg.Network.ProxyURL != "" {
		// Simple parsing for tests
		parts := strings.SplitN(cfg.Network.ProxyURL, "://", 2)
		if len(parts) == 2 {
			hostPort := parts[1]
			colonIdx := strings.LastIndex(hostPort, ":")
			if colonIdx >= 0 {
				proxyHost = hostPort[:colonIdx]
				proxyPort = hostPort[colonIdx+1:]
			}
		}
	}

	return MacOSSandboxParams{
		Command:                 "echo test",
		NeedsNetworkRestriction: true,
		ProxyURL:                cfg.Network.ProxyURL,
		ProxyHost:               proxyHost,
		ProxyPort:               proxyPort,
		AllowUnixSockets:        cfg.Network.AllowUnixSockets,
		AllowAllUnixSockets:     cfg.Network.AllowAllUnixSockets,
		AllowLocalBinding:       allowLocalBinding,
		AllowLocalOutbound:      allowLocalOutbound,
		DefaultDenyRead:         cfg.Filesystem.IsDefaultDenyRead(),
		Cwd:                     "/tmp/test-project",
		ReadAllowPaths:          cfg.Filesystem.AllowRead,
		ReadDenyPaths:           cfg.Filesystem.DenyRead,
		WriteAllowPaths:         allowPaths,
		WriteDenyPaths:          cfg.Filesystem.DenyWrite,
		AllowPty:                cfg.AllowPty,
		AllowGitConfig:          cfg.Filesystem.AllowGitConfig,
	}
}

// TestMacOS_ProfileNetworkSection verifies the network section of generated profiles.
func TestMacOS_ProfileNetworkSection(t *testing.T) {
	tests := []struct {
		name           string
		restricted     bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:       "unrestricted network allows all",
			restricted: false,
			wantContains: []string{
				"(allow network*)", // Blanket allow all network operations
			},
			wantNotContain: []string{},
		},
		{
			name:       "restricted network does not allow all",
			restricted: true,
			wantContains: []string{
				"; Network", // Should have network section
			},
			wantNotContain: []string{
				"(allow network*)", // Should NOT have blanket allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:                 "echo test",
				NeedsNetworkRestriction: tt.restricted,
			}

			profile := GenerateSandboxProfile(params)

			for _, want := range tt.wantContains {
				if !strings.Contains(profile, want) {
					t.Errorf("profile should contain %q, got:\n%s", want, profile)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(profile, notWant) {
					t.Errorf("profile should NOT contain %q", notWant)
				}
			}
		})
	}
}

// TestMacOS_DefaultDenyRead verifies that the defaultDenyRead option properly restricts filesystem reads.
func TestMacOS_DefaultDenyRead(t *testing.T) {
	tests := []struct {
		name                      string
		defaultDenyRead           bool
		cwd                       string
		allowRead                 []string
		wantContainsBlanketAllow  bool
		wantContainsMetadataAllow bool
		wantContainsSystemAllows  bool
		wantContainsUserAllowRead bool
		wantContainsCwdAllow      bool
	}{
		{
			name:                      "legacy mode - blanket allow read",
			defaultDenyRead:           false,
			cwd:                       "/home/user/project",
			allowRead:                 nil,
			wantContainsBlanketAllow:  true,
			wantContainsMetadataAllow: false,
			wantContainsSystemAllows:  false,
			wantContainsUserAllowRead: false,
			wantContainsCwdAllow:      false,
		},
		{
			name:                      "defaultDenyRead enabled - metadata allow, system data allows, CWD allow",
			defaultDenyRead:           true,
			cwd:                       "/home/user/project",
			allowRead:                 nil,
			wantContainsBlanketAllow:  false,
			wantContainsMetadataAllow: true,
			wantContainsSystemAllows:  true,
			wantContainsUserAllowRead: false,
			wantContainsCwdAllow:      true,
		},
		{
			name:                      "defaultDenyRead with allowRead paths",
			defaultDenyRead:           true,
			cwd:                       "/home/user/project",
			allowRead:                 []string{"/home/user/other"},
			wantContainsBlanketAllow:  false,
			wantContainsMetadataAllow: true,
			wantContainsSystemAllows:  true,
			wantContainsUserAllowRead: true,
			wantContainsCwdAllow:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:         "echo test",
				DefaultDenyRead: tt.defaultDenyRead,
				Cwd:             tt.cwd,
				ReadAllowPaths:  tt.allowRead,
			}

			profile := GenerateSandboxProfile(params)

			hasBlanketAllow := strings.Contains(profile, "(allow file-read*)\n")
			if hasBlanketAllow != tt.wantContainsBlanketAllow {
				t.Errorf("blanket file-read allow = %v, want %v", hasBlanketAllow, tt.wantContainsBlanketAllow)
			}

			hasMetadataAllow := strings.Contains(profile, "(allow file-read-metadata)")
			if hasMetadataAllow != tt.wantContainsMetadataAllow {
				t.Errorf("file-read-metadata allow = %v, want %v", hasMetadataAllow, tt.wantContainsMetadataAllow)
			}

			hasSystemAllows := strings.Contains(profile, `(subpath "/usr")`) ||
				strings.Contains(profile, `(subpath "/bin")`)
			if hasSystemAllows != tt.wantContainsSystemAllows {
				t.Errorf("system path allows = %v, want %v\nProfile:\n%s", hasSystemAllows, tt.wantContainsSystemAllows, profile)
			}

			if tt.wantContainsCwdAllow && tt.cwd != "" {
				hasCwdAllow := strings.Contains(profile, fmt.Sprintf(`(subpath %q)`, tt.cwd))
				if !hasCwdAllow {
					t.Errorf("CWD path %q not found in profile", tt.cwd)
				}
			}

			if tt.wantContainsUserAllowRead && len(tt.allowRead) > 0 {
				hasUserAllow := strings.Contains(profile, tt.allowRead[0])
				if !hasUserAllow {
					t.Errorf("user allowRead path %q not found in profile", tt.allowRead[0])
				}
			}
		})
	}
}

// TestMacOS_DenyReadUsesExactOperation verifies that deny read rules use file-read-data
// (not file-read*) in the generated Seatbelt profile. Seatbelt ignores wildcard denies
// (file-read*) when a specific allow (file-read-data) covers the same path.
func TestMacOS_DenyReadUsesExactOperation(t *testing.T) {
	tests := []struct {
		name            string
		defaultDenyRead bool
		denyRead        []string
		cwd             string
	}{
		{
			name:            "defaultDenyRead with sensitive project files",
			defaultDenyRead: true,
			denyRead:        nil,
			cwd:             "/home/user/project",
		},
		{
			name:            "defaultDenyRead with user denyRead paths",
			defaultDenyRead: true,
			denyRead:        []string{"/home/user/secrets", "/home/user/.ssh/id_*"},
			cwd:             "/home/user/project",
		},
		{
			name:            "legacy mode with user denyRead paths",
			defaultDenyRead: false,
			denyRead:        []string{"/home/user/secrets"},
			cwd:             "/home/user/project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:         "echo test",
				DefaultDenyRead: tt.defaultDenyRead,
				Cwd:             tt.cwd,
				ReadDenyPaths:   tt.denyRead,
			}

			profile := GenerateSandboxProfile(params)

			// Must NOT contain "deny file-read*" (wildcard deny is ineffective)
			if strings.Contains(profile, "(deny file-read*") {
				t.Errorf("profile must NOT use 'deny file-read*' (wildcard deny is ignored by Seatbelt when a specific allow covers the same path)\nProfile:\n%s", profile)
			}

			// Must contain "deny file-read-data" for deny rules to work
			if tt.defaultDenyRead || len(tt.denyRead) > 0 {
				if !strings.Contains(profile, "(deny file-read-data") {
					t.Errorf("profile must use 'deny file-read-data' for deny rules to be effective\nProfile:\n%s", profile)
				}
			}
		})
	}
}

// TestMacOS_DenyReadSensitiveProjectFiles verifies that the generated profile
// contains deny rules for all sensitive project files (.env, .env.local, etc.).
func TestMacOS_DenyReadSensitiveProjectFiles(t *testing.T) {
	cwd := "/home/user/project"
	params := MacOSSandboxParams{
		Command:         "cat .env",
		DefaultDenyRead: true,
		Cwd:             cwd,
	}

	profile := GenerateSandboxProfile(params)

	for _, f := range SensitiveProjectFiles {
		expected := fmt.Sprintf(`(deny file-read-data
  (literal %q)`, cwd+"/"+f)
		if !strings.Contains(profile, expected) {
			t.Errorf("profile missing deny rule for sensitive file %q\nExpected to contain: %s", f, expected)
		}
	}

	// Also check .env.* regex pattern
	if !strings.Contains(profile, `(deny file-read-data
  (regex`) {
		t.Errorf("profile missing regex deny rule for .env.* pattern")
	}
}

// TestMacOS_DenyReadUserPaths verifies that user-configured denyRead paths
// appear in the generated profile with file-read-data (not file-read*).
func TestMacOS_DenyReadUserPaths(t *testing.T) {
	params := MacOSSandboxParams{
		Command:         "echo test",
		DefaultDenyRead: false,
		Cwd:             "/home/user/project",
		ReadDenyPaths:   []string{"/home/user/secrets"},
	}

	profile := GenerateSandboxProfile(params)

	expected := `(deny file-read-data
  (subpath "/home/user/secrets")`
	if !strings.Contains(profile, expected) {
		t.Errorf("profile missing deny rule for user denyRead path\nExpected: %s\nProfile:\n%s", expected, profile)
	}
}

// TestExpandMacOSTmpPaths verifies that /tmp and /private/tmp paths are properly mirrored.
func TestExpandMacOSTmpPaths(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "mirrors /tmp to /private/tmp",
			input: []string{".", "/tmp"},
			want:  []string{".", "/tmp", "/private/tmp"},
		},
		{
			name:  "mirrors /private/tmp to /tmp",
			input: []string{".", "/private/tmp"},
			want:  []string{".", "/private/tmp", "/tmp"},
		},
		{
			name:  "no change when both present",
			input: []string{".", "/tmp", "/private/tmp"},
			want:  []string{".", "/tmp", "/private/tmp"},
		},
		{
			name:  "no change when neither present",
			input: []string{".", "~/.cache"},
			want:  []string{".", "~/.cache"},
		},
		{
			name:  "mirrors /tmp/greywall to /private/tmp/greywall",
			input: []string{".", "/tmp/greywall"},
			want:  []string{".", "/tmp/greywall", "/private/tmp/greywall"},
		},
		{
			name:  "mirrors /private/tmp/greywall to /tmp/greywall",
			input: []string{".", "/private/tmp/greywall"},
			want:  []string{".", "/private/tmp/greywall", "/tmp/greywall"},
		},
		{
			name:  "mirrors nested subdirectory",
			input: []string{".", "/tmp/foo/bar"},
			want:  []string{".", "/tmp/foo/bar", "/private/tmp/foo/bar"},
		},
		{
			name:  "no duplicate when mirror already present",
			input: []string{".", "/tmp/greywall", "/private/tmp/greywall"},
			want:  []string{".", "/tmp/greywall", "/private/tmp/greywall"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandMacOSTmpPaths(tt.input)

			if len(got) != len(tt.want) {
				t.Errorf("expandMacOSTmpPaths() = %v, want %v", got, tt.want)
				return
			}

			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("expandMacOSTmpPaths()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}
