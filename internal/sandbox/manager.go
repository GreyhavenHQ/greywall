package sandbox

import (
	"fmt"
	"os"

	"gitea.app.monadical.io/monadical/greywall/internal/config"
	"gitea.app.monadical.io/monadical/greywall/internal/platform"
)

// Manager handles sandbox initialization and command wrapping.
type Manager struct {
	config        *config.Config
	proxyBridge   *ProxyBridge
	dnsBridge     *DnsBridge
	reverseBridge *ReverseBridge
	tun2socksPath string // path to extracted tun2socks binary on host
	exposedPorts  []int
	debug         bool
	monitor       bool
	initialized   bool
	learning      bool   // learning mode: permissive sandbox with strace
	straceLogPath string // host-side temp file for strace output
	commandName   string // name of the command being learned
}

// NewManager creates a new sandbox manager.
func NewManager(cfg *config.Config, debug, monitor bool) *Manager {
	return &Manager{
		config:  cfg,
		debug:   debug,
		monitor: monitor,
	}
}

// SetExposedPorts sets the ports to expose for inbound connections.
func (m *Manager) SetExposedPorts(ports []int) {
	m.exposedPorts = ports
}

// SetLearning enables or disables learning mode.
func (m *Manager) SetLearning(enabled bool) {
	m.learning = enabled
}

// SetCommandName sets the command name for learning mode template generation.
func (m *Manager) SetCommandName(name string) {
	m.commandName = name
}

// IsLearning returns whether learning mode is enabled.
func (m *Manager) IsLearning() bool {
	return m.learning
}

// Initialize sets up the sandbox infrastructure.
func (m *Manager) Initialize() error {
	if m.initialized {
		return nil
	}

	if !platform.IsSupported() {
		return fmt.Errorf("sandbox is not supported on platform: %s", platform.Detect())
	}

	// On Linux, set up proxy bridge and tun2socks if proxy is configured
	if platform.Detect() == platform.Linux {
		if m.config.Network.ProxyURL != "" {
			// Extract embedded tun2socks binary
			tun2socksPath, err := extractTun2Socks()
			if err != nil {
				m.logDebug("Failed to extract tun2socks: %v (will fall back to env-var proxying)", err)
			} else {
				m.tun2socksPath = tun2socksPath
			}

			// Create proxy bridge (socat: Unix socket -> external SOCKS5 proxy)
			bridge, err := NewProxyBridge(m.config.Network.ProxyURL, m.debug)
			if err != nil {
				if m.tun2socksPath != "" {
					os.Remove(m.tun2socksPath)
				}
				return fmt.Errorf("failed to initialize proxy bridge: %w", err)
			}
			m.proxyBridge = bridge

			// Create DNS bridge if a DNS server is configured
			if m.config.Network.DnsAddr != "" {
				dnsBridge, err := NewDnsBridge(m.config.Network.DnsAddr, m.debug)
				if err != nil {
					m.proxyBridge.Cleanup()
					if m.tun2socksPath != "" {
						os.Remove(m.tun2socksPath)
					}
					return fmt.Errorf("failed to initialize DNS bridge: %w", err)
				}
				m.dnsBridge = dnsBridge
			}
		}

		// Set up reverse bridge for exposed ports (inbound connections)
		// Only needed when network namespace is available - otherwise they share the network
		features := DetectLinuxFeatures()
		if len(m.exposedPorts) > 0 && features.CanUnshareNet {
			reverseBridge, err := NewReverseBridge(m.exposedPorts, m.debug)
			if err != nil {
				if m.proxyBridge != nil {
					m.proxyBridge.Cleanup()
				}
				if m.tun2socksPath != "" {
					os.Remove(m.tun2socksPath)
				}
				return fmt.Errorf("failed to initialize reverse bridge: %w", err)
			}
			m.reverseBridge = reverseBridge
		} else if len(m.exposedPorts) > 0 && m.debug {
			m.logDebug("Skipping reverse bridge (no network namespace, ports accessible directly)")
		}
	}

	m.initialized = true
	if m.config.Network.ProxyURL != "" {
		m.logDebug("Sandbox manager initialized (proxy: %s)", m.config.Network.ProxyURL)
	} else {
		m.logDebug("Sandbox manager initialized (no proxy, network blocked)")
	}
	return nil
}

// WrapCommand wraps a command with sandbox restrictions.
// Returns an error if the command is blocked by policy.
func (m *Manager) WrapCommand(command string) (string, error) {
	if !m.initialized {
		if err := m.Initialize(); err != nil {
			return "", err
		}
	}

	// Check if command is blocked by policy
	if err := CheckCommand(command, m.config); err != nil {
		return "", err
	}

	plat := platform.Detect()
	switch plat {
	case platform.MacOS:
		return WrapCommandMacOS(m.config, command, m.exposedPorts, m.debug)
	case platform.Linux:
		if m.learning {
			return m.wrapCommandLearning(command)
		}
		return WrapCommandLinux(m.config, command, m.proxyBridge, m.dnsBridge, m.reverseBridge, m.tun2socksPath, m.debug)
	default:
		return "", fmt.Errorf("unsupported platform: %s", plat)
	}
}

// wrapCommandLearning creates a permissive sandbox with strace for learning mode.
func (m *Manager) wrapCommandLearning(command string) (string, error) {
	// Create host-side temp file for strace output
	tmpFile, err := os.CreateTemp("", "greywall-strace-*.log")
	if err != nil {
		return "", fmt.Errorf("failed to create strace log file: %w", err)
	}
	tmpFile.Close()
	m.straceLogPath = tmpFile.Name()

	m.logDebug("Strace log file: %s", m.straceLogPath)

	return WrapCommandLinuxWithOptions(m.config, command, m.proxyBridge, m.dnsBridge, m.reverseBridge, m.tun2socksPath, LinuxSandboxOptions{
		UseLandlock:   false, // Disabled: seccomp blocks ptrace which strace needs
		UseSeccomp:    false, // Disabled: conflicts with strace
		UseEBPF:       false,
		Debug:         m.debug,
		Learning:      true,
		StraceLogPath: m.straceLogPath,
	})
}

// GenerateLearnedTemplate generates a config template from the strace log collected during learning.
func (m *Manager) GenerateLearnedTemplate(cmdName string) (string, error) {
	if m.straceLogPath == "" {
		return "", fmt.Errorf("no strace log available (was learning mode enabled?)")
	}

	templatePath, err := GenerateLearnedTemplate(m.straceLogPath, cmdName, m.debug)
	if err != nil {
		return "", err
	}

	// Clean up strace log since we've processed it
	os.Remove(m.straceLogPath)
	m.straceLogPath = ""

	return templatePath, nil
}

// Cleanup stops the proxies and cleans up resources.
func (m *Manager) Cleanup() {
	if m.reverseBridge != nil {
		m.reverseBridge.Cleanup()
	}
	if m.dnsBridge != nil {
		m.dnsBridge.Cleanup()
	}
	if m.proxyBridge != nil {
		m.proxyBridge.Cleanup()
	}
	if m.tun2socksPath != "" {
		os.Remove(m.tun2socksPath)
	}
	if m.straceLogPath != "" {
		os.Remove(m.straceLogPath)
		m.straceLogPath = ""
	}
	m.logDebug("Sandbox manager cleaned up")
}

func (m *Manager) logDebug(format string, args ...interface{}) {
	if m.debug {
		fmt.Fprintf(os.Stderr, "[greywall] "+format+"\n", args...)
	}
}
