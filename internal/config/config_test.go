package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "valid empty config",
			config:  Config{},
			wantErr: false,
		},
		{
			name: "valid config with proxy",
			config: Config{
				Network: NetworkConfig{
					ProxyURL: "socks5://localhost:1080",
				},
			},
			wantErr: false,
		},
		{
			name: "valid socks5h proxy",
			config: Config{
				Network: NetworkConfig{
					ProxyURL: "socks5h://proxy.example.com:1080",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid proxy - wrong scheme",
			config: Config{
				Network: NetworkConfig{
					ProxyURL: "http://localhost:1080",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid proxy - no port",
			config: Config{
				Network: NetworkConfig{
					ProxyURL: "socks5://localhost",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid proxy - no host",
			config: Config{
				Network: NetworkConfig{
					ProxyURL: "socks5://:1080",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid proxy - not a URL",
			config: Config{
				Network: NetworkConfig{
					ProxyURL: "not-a-url",
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowRead path",
			config: Config{
				Filesystem: FilesystemConfig{
					AllowRead: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denyRead path",
			config: Config{
				Filesystem: FilesystemConfig{
					DenyRead: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowWrite path",
			config: Config{
				Filesystem: FilesystemConfig{
					AllowWrite: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denyWrite path",
			config: Config{
				Filesystem: FilesystemConfig{
					DenyWrite: []string{""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
	if cfg.Network.ProxyURL != "" {
		t.Error("ProxyURL should be empty by default")
	}
	if cfg.Filesystem.DenyRead == nil {
		t.Error("DenyRead should not be nil")
	}
	if cfg.Filesystem.AllowWrite == nil {
		t.Error("AllowWrite should not be nil")
	}
	if cfg.Filesystem.DenyWrite == nil {
		t.Error("DenyWrite should not be nil")
	}
}

func TestLoad(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		setup       func(string) string // returns path
		wantNil     bool
		wantErr     bool
		checkConfig func(*testing.T, *Config)
	}{
		{
			name:    "nonexistent file",
			setup:   func(dir string) string { return filepath.Join(dir, "nonexistent.json") },
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "empty file",
			content: "",
			setup: func(dir string) string {
				path := filepath.Join(dir, "empty.json")
				_ = os.WriteFile(path, []byte(""), 0o600)
				return path
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "whitespace only file",
			content: "   \n\t  ",
			setup: func(dir string) string {
				path := filepath.Join(dir, "whitespace.json")
				_ = os.WriteFile(path, []byte("   \n\t  "), 0o600)
				return path
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid config with proxy",
			setup: func(dir string) string {
				path := filepath.Join(dir, "valid.json")
				content := `{"network":{"proxyUrl":"socks5://localhost:1080"}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: false,
			checkConfig: func(t *testing.T, cfg *Config) {
				if cfg.Network.ProxyURL != "socks5://localhost:1080" {
					t.Errorf("expected socks5://localhost:1080, got %s", cfg.Network.ProxyURL)
				}
			},
		},
		{
			name: "invalid JSON",
			setup: func(dir string) string {
				path := filepath.Join(dir, "invalid.json")
				_ = os.WriteFile(path, []byte("{invalid json}"), 0o600)
				return path
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "invalid proxy URL in config",
			setup: func(dir string) string {
				path := filepath.Join(dir, "invalid_proxy.json")
				content := `{"network":{"proxyUrl":"http://localhost:1080"}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(tmpDir)
			cfg, err := Load(path)

			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && cfg != nil {
				t.Error("Load() expected nil config")
				return
			}

			if !tt.wantNil && !tt.wantErr && cfg == nil {
				t.Error("Load() returned nil config unexpectedly")
				return
			}

			if tt.checkConfig != nil && cfg != nil {
				tt.checkConfig(t, cfg)
			}
		})
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("DefaultConfigPath() returned empty string")
	}
	// Should end with greywall.json (either new XDG path or legacy .greywall.json)
	base := filepath.Base(path)
	if base != "greywall.json" && base != ".greywall.json" {
		t.Errorf("DefaultConfigPath() = %q, expected to end with greywall.json or .greywall.json", path)
	}
}

func TestMerge(t *testing.T) {
	t.Run("nil base", func(t *testing.T) {
		override := &Config{
			AllowPty: true,
			Network: NetworkConfig{
				ProxyURL: "socks5://localhost:1080",
			},
		}
		result := Merge(nil, override)
		if !result.AllowPty {
			t.Error("expected AllowPty to be true")
		}
		if result.Network.ProxyURL != "socks5://localhost:1080" {
			t.Error("expected ProxyURL to be socks5://localhost:1080")
		}
		if result.Extends != "" {
			t.Error("expected Extends to be cleared")
		}
	})

	t.Run("nil override", func(t *testing.T) {
		base := &Config{
			AllowPty: true,
			Network: NetworkConfig{
				ProxyURL: "socks5://localhost:1080",
			},
		}
		result := Merge(base, nil)
		if !result.AllowPty {
			t.Error("expected AllowPty to be true")
		}
		if result.Network.ProxyURL != "socks5://localhost:1080" {
			t.Error("expected ProxyURL to be preserved")
		}
	})

	t.Run("both nil", func(t *testing.T) {
		result := Merge(nil, nil)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("proxy URL override wins", func(t *testing.T) {
		base := &Config{
			Network: NetworkConfig{
				ProxyURL: "socks5://base:1080",
			},
		}
		override := &Config{
			Network: NetworkConfig{
				ProxyURL: "socks5://override:1080",
			},
		}
		result := Merge(base, override)

		if result.Network.ProxyURL != "socks5://override:1080" {
			t.Errorf("expected override ProxyURL, got %s", result.Network.ProxyURL)
		}
	})

	t.Run("proxy URL base preserved when override empty", func(t *testing.T) {
		base := &Config{
			Network: NetworkConfig{
				ProxyURL: "socks5://base:1080",
			},
		}
		override := &Config{
			Network: NetworkConfig{},
		}
		result := Merge(base, override)

		if result.Network.ProxyURL != "socks5://base:1080" {
			t.Errorf("expected base ProxyURL, got %s", result.Network.ProxyURL)
		}
	})

	t.Run("merge boolean flags", func(t *testing.T) {
		base := &Config{
			AllowPty: false,
			Network: NetworkConfig{
				AllowLocalBinding: true,
			},
		}
		override := &Config{
			AllowPty: true,
			Network: NetworkConfig{
				AllowLocalOutbound: boolPtr(true),
			},
		}
		result := Merge(base, override)

		if !result.AllowPty {
			t.Error("expected AllowPty to be true (from override)")
		}
		if !result.Network.AllowLocalBinding {
			t.Error("expected AllowLocalBinding to be true (from base)")
		}
		if result.Network.AllowLocalOutbound == nil || !*result.Network.AllowLocalOutbound {
			t.Error("expected AllowLocalOutbound to be true (from override)")
		}
	})

	t.Run("merge command config", func(t *testing.T) {
		base := &Config{
			Command: CommandConfig{
				Deny: []string{"git push", "rm -rf"},
			},
		}
		override := &Config{
			Command: CommandConfig{
				Deny:  []string{"sudo"},
				Allow: []string{"git status"},
			},
		}
		result := Merge(base, override)

		if len(result.Command.Deny) != 3 {
			t.Errorf("expected 3 denied commands, got %d", len(result.Command.Deny))
		}
		if len(result.Command.Allow) != 1 {
			t.Errorf("expected 1 allowed command, got %d", len(result.Command.Allow))
		}
	})

	t.Run("merge filesystem config", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				AllowWrite: []string{"."},
				DenyRead:   []string{"~/.ssh/**"},
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				AllowWrite: []string{"/tmp"},
				DenyWrite:  []string{".env"},
			},
		}
		result := Merge(base, override)

		if len(result.Filesystem.AllowWrite) != 2 {
			t.Errorf("expected 2 write paths, got %d", len(result.Filesystem.AllowWrite))
		}
		if len(result.Filesystem.DenyRead) != 1 {
			t.Errorf("expected 1 deny read path, got %d", len(result.Filesystem.DenyRead))
		}
		if len(result.Filesystem.DenyWrite) != 1 {
			t.Errorf("expected 1 deny write path, got %d", len(result.Filesystem.DenyWrite))
		}
	})

	t.Run("merge defaultDenyRead and allowRead", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				DefaultDenyRead: boolPtr(true),
				AllowRead:       []string{"/home/user/project"},
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				AllowRead: []string{"/home/user/other"},
			},
		}
		result := Merge(base, override)

		if !result.Filesystem.IsDefaultDenyRead() {
			t.Error("expected IsDefaultDenyRead() to be true (from base)")
		}
		if len(result.Filesystem.AllowRead) != 2 {
			t.Errorf("expected 2 allowRead paths, got %d: %v", len(result.Filesystem.AllowRead), result.Filesystem.AllowRead)
		}
	})

	t.Run("defaultDenyRead nil defaults to true", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{},
		}
		result := Merge(base, nil)
		if !result.Filesystem.IsDefaultDenyRead() {
			t.Error("expected IsDefaultDenyRead() to be true when nil (deny-by-default)")
		}
	})

	t.Run("defaultDenyRead explicit false overrides", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				DefaultDenyRead: boolPtr(true),
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				DefaultDenyRead: boolPtr(false),
			},
		}
		result := Merge(base, override)
		if result.Filesystem.IsDefaultDenyRead() {
			t.Error("expected IsDefaultDenyRead() to be false (override explicit false)")
		}
	})
}

func boolPtr(b bool) *bool {
	return &b
}

func TestValidateHostPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		// Valid patterns
		{"simple hostname", "server1", false},
		{"domain", "example.com", false},
		{"subdomain", "prod.example.com", false},
		{"wildcard prefix", "*.example.com", false},
		{"wildcard middle", "prod-*.example.com", false},
		{"ip address", "192.168.1.1", false},
		{"ipv6 address", "::1", false},
		{"ipv6 full", "2001:db8::1", false},
		{"localhost", "localhost", false},

		// Invalid patterns
		{"empty", "", true},
		{"with protocol", "ssh://example.com", true},
		{"with path", "example.com/path", true},
		{"with port", "example.com:22", true},
		{"with username", "user@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHostPattern(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestMatchesHost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
		want     bool
	}{
		// Exact matches
		{"exact match", "server1.example.com", "server1.example.com", true},
		{"exact match case insensitive", "Server1.Example.COM", "server1.example.com", true},
		{"exact no match", "server2.example.com", "server1.example.com", false},

		// Wildcard matches
		{"wildcard prefix", "api.example.com", "*.example.com", true},
		{"wildcard prefix deep", "deep.api.example.com", "*.example.com", true},
		{"wildcard no match base", "example.com", "*.example.com", false},
		{"wildcard middle", "prod-web-01.example.com", "prod-*.example.com", true},
		{"wildcard middle no match", "dev-web-01.example.com", "prod-*.example.com", false},
		{"wildcard suffix", "server1.prod", "server1.*", true},
		{"multiple wildcards", "prod-web-01.us-east.example.com", "prod-*-*.example.com", true},

		// Star matches all
		{"star matches all", "anything.example.com", "*", true},

		// IP addresses
		{"ip exact match", "192.168.1.1", "192.168.1.1", true},
		{"ip no match", "192.168.1.2", "192.168.1.1", false},
		{"ip wildcard", "192.168.1.100", "192.168.1.*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesHost(tt.hostname, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesHost(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestSSHConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid SSH config",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts:    []string{"*.example.com", "prod-*.internal"},
					AllowedCommands: []string{"ls", "cat", "grep"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid allowed host with protocol",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts: []string{"ssh://example.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid denied host with username",
			config: Config{
				SSH: SSHConfig{
					DeniedHosts: []string{"user@example.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowed command",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts:    []string{"example.com"},
					AllowedCommands: []string{"ls", ""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denied command",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts:   []string{"example.com"},
					DeniedCommands: []string{""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMergeSSHConfig(t *testing.T) {
	t.Run("merge SSH allowed hosts", func(t *testing.T) {
		base := &Config{
			SSH: SSHConfig{
				AllowedHosts: []string{"prod-*.example.com"},
			},
		}
		override := &Config{
			SSH: SSHConfig{
				AllowedHosts: []string{"dev-*.example.com"},
			},
		}
		result := Merge(base, override)

		if len(result.SSH.AllowedHosts) != 2 {
			t.Errorf("expected 2 allowed hosts, got %d: %v", len(result.SSH.AllowedHosts), result.SSH.AllowedHosts)
		}
	})

	t.Run("merge SSH commands", func(t *testing.T) {
		base := &Config{
			SSH: SSHConfig{
				AllowedCommands: []string{"ls", "cat"},
				DeniedCommands:  []string{"rm -rf"},
			},
		}
		override := &Config{
			SSH: SSHConfig{
				AllowedCommands: []string{"grep", "find"},
				DeniedCommands:  []string{"shutdown"},
			},
		}
		result := Merge(base, override)

		if len(result.SSH.AllowedCommands) != 4 {
			t.Errorf("expected 4 allowed commands, got %d", len(result.SSH.AllowedCommands))
		}
		if len(result.SSH.DeniedCommands) != 2 {
			t.Errorf("expected 2 denied commands, got %d", len(result.SSH.DeniedCommands))
		}
	})

	t.Run("merge SSH boolean flags", func(t *testing.T) {
		base := &Config{
			SSH: SSHConfig{
				AllowAllCommands: false,
				InheritDeny:      true,
			},
		}
		override := &Config{
			SSH: SSHConfig{
				AllowAllCommands: true,
				InheritDeny:      false,
			},
		}
		result := Merge(base, override)

		if !result.SSH.AllowAllCommands {
			t.Error("expected AllowAllCommands to be true (OR logic)")
		}
		if !result.SSH.InheritDeny {
			t.Error("expected InheritDeny to be true (OR logic)")
		}
	})
}

func TestMergeForwardPorts(t *testing.T) {
	t.Run("merge forward ports deduplicates", func(t *testing.T) {
		base := &Config{
			Network: NetworkConfig{
				ForwardPorts: []int{5432, 6379},
			},
		}
		override := &Config{
			Network: NetworkConfig{
				ForwardPorts: []int{6379, 8080},
			},
		}
		result := Merge(base, override)

		if len(result.Network.ForwardPorts) != 3 {
			t.Errorf("expected 3 forward ports, got %d: %v", len(result.Network.ForwardPorts), result.Network.ForwardPorts)
		}
		expected := map[int]bool{5432: true, 6379: true, 8080: true}
		for _, p := range result.Network.ForwardPorts {
			if !expected[p] {
				t.Errorf("unexpected port %d in merged result", p)
			}
		}
	})

	t.Run("merge forward ports empty base", func(t *testing.T) {
		base := &Config{}
		override := &Config{
			Network: NetworkConfig{
				ForwardPorts: []int{3000},
			},
		}
		result := Merge(base, override)

		if len(result.Network.ForwardPorts) != 1 || result.Network.ForwardPorts[0] != 3000 {
			t.Errorf("expected [3000], got %v", result.Network.ForwardPorts)
		}
	})

	t.Run("merge forward ports empty override", func(t *testing.T) {
		base := &Config{
			Network: NetworkConfig{
				ForwardPorts: []int{3000},
			},
		}
		override := &Config{}
		result := Merge(base, override)

		if len(result.Network.ForwardPorts) != 1 || result.Network.ForwardPorts[0] != 3000 {
			t.Errorf("expected [3000], got %v", result.Network.ForwardPorts)
		}
	})
}

func TestValidateProxyURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid socks5", "socks5://localhost:1080", false},
		{"valid socks5h", "socks5h://proxy.example.com:1080", false},
		{"valid socks5 with ip", "socks5://192.168.1.1:1080", false},
		{"http scheme", "http://localhost:1080", true},
		{"https scheme", "https://localhost:1080", true},
		{"no port", "socks5://localhost", true},
		{"no host", "socks5://:1080", true},
		{"not a URL", "not-a-url", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProxyURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateProxyURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
