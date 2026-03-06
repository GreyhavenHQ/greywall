package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/platform"
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
	learning      bool   // learning mode: permissive sandbox with strace/eslogger
	straceLogPath string // host-side temp file for strace output (Linux)
	commandName   string // name of the command being learned
	// macOS learning mode fields
	learningRootPID int       // root PID of the sandboxed command (for eslogger PID tree tracking)
	esloggerLogPath string    // temp file for eslogger output (macOS)
	esloggerCmd     *exec.Cmd // eslogger subprocess (macOS)
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

	// On macOS in learning mode, launch eslogger via sudo to trace filesystem access.
	// Only eslogger itself needs root (Endpoint Security framework) — the sandboxed
	// command runs as the current user.
	if platform.Detect() == platform.MacOS && m.learning {
		logFile, err := os.CreateTemp("", "greywall-eslogger-*.log")
		if err != nil {
			return fmt.Errorf("failed to create eslogger log file: %w", err)
		}
		m.esloggerLogPath = logFile.Name()
		m.logDebug("Starting eslogger (via sudo), log: %s", m.esloggerLogPath)

		// Validate sudo credentials upfront so the password prompt happens before
		// the user's command starts (which may take over the terminal).
		//nolint:gosec // sudo path is hardcoded
		sudoValidate := exec.Command("/usr/bin/sudo", "-v")
		sudoValidate.Stdin = os.Stdin
		sudoValidate.Stdout = os.Stderr
		sudoValidate.Stderr = os.Stderr
		if err := sudoValidate.Run(); err != nil {
			_ = logFile.Close()
			_ = os.Remove(m.esloggerLogPath)
			return fmt.Errorf("sudo authentication failed (needed for eslogger): %w", err)
		}

		//nolint:gosec // eslogger and sudo paths are hardcoded, event types are constants
		cmd := exec.Command("/usr/bin/sudo", "/usr/bin/eslogger", "open", "create", "write", "unlink", "truncate", "rename", "link", "fork")
		cmd.Stdout = logFile
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			_ = logFile.Close()
			_ = os.Remove(m.esloggerLogPath)
			return fmt.Errorf("failed to start eslogger: %w", err)
		}
		m.esloggerCmd = cmd
		_ = logFile.Close() // eslogger owns the fd now via its stdout

		// Wait for eslogger to connect to Endpoint Security and start emitting events.
		// Once connected, it immediately logs events from all processes on the system,
		// so any data in the log file means it's ready.
		m.logDebug("Waiting for eslogger to become ready...")
		ready := false
		for range 50 { // up to 5 seconds
			info, err := os.Stat(m.esloggerLogPath)
			if err == nil && info.Size() > 0 {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			m.logDebug("eslogger did not produce output within 5s, proceeding anyway")
		} else {
			m.logDebug("eslogger is ready")
		}

		m.initialized = true
		return nil
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
					_ = os.Remove(m.tun2socksPath)
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
						_ = os.Remove(m.tun2socksPath)
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
					_ = os.Remove(m.tun2socksPath)
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
		dnsInfo := "none"
		if m.config.Network.DnsAddr != "" {
			dnsInfo = m.config.Network.DnsAddr
		}
		m.logDebug("Sandbox manager initialized (proxy: %s, dns: %s)", m.config.Network.ProxyURL, dnsInfo)
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
		if m.learning {
			// In learning mode, run command directly (no sandbox-exec wrapping)
			return command, nil
		}
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

// wrapCommandLearning creates a permissive sandbox with strace for learning mode (Linux).
func (m *Manager) wrapCommandLearning(command string) (string, error) {
	// Create host-side temp file for strace output
	tmpFile, err := os.CreateTemp("", "greywall-strace-*.log")
	if err != nil {
		return "", fmt.Errorf("failed to create strace log file: %w", err)
	}
	_ = tmpFile.Close()
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

// GenerateLearnedTemplate generates a config template from the trace log collected during learning.
// Platform-specific implementation in manager_linux.go / manager_darwin.go.
func (m *Manager) GenerateLearnedTemplate(cmdName string) (string, error) {
	return m.generateLearnedTemplatePlatform(cmdName)
}

// SetLearningRootPID records the root PID of the command being learned.
// The eslogger log parser uses this to build the process tree from fork events.
func (m *Manager) SetLearningRootPID(pid int) {
	m.learningRootPID = pid
	m.logDebug("Set learning root PID: %d", pid)
}

// Cleanup stops the proxies and cleans up resources.
func (m *Manager) Cleanup() {
	// Stop macOS eslogger if running
	if m.esloggerCmd != nil && m.esloggerCmd.Process != nil {
		m.logDebug("Stopping eslogger (PID %d)", m.esloggerCmd.Process.Pid)
		_ = m.esloggerCmd.Process.Signal(os.Interrupt)
		_ = m.esloggerCmd.Wait()
		m.esloggerCmd = nil
	}

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
		_ = os.Remove(m.tun2socksPath)
	}
	if m.straceLogPath != "" {
		_ = os.Remove(m.straceLogPath)
		m.straceLogPath = ""
	}
	if m.esloggerLogPath != "" {
		_ = os.Remove(m.esloggerLogPath)
		m.esloggerLogPath = ""
	}
	m.logDebug("Sandbox manager cleaned up")
}

func (m *Manager) logDebug(format string, args ...interface{}) {
	if m.debug {
		fmt.Fprintf(os.Stderr, "[greywall] "+format+"\n", args...)
	}
}
