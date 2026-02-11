//go:build !linux

package sandbox

import (
	"fmt"

	"gitea.app.monadical.io/monadical/greywall/internal/config"
)

// ProxyBridge is a stub for non-Linux platforms.
type ProxyBridge struct {
	SocketPath string
	ProxyHost  string
	ProxyPort  string
}

// DnsBridge is a stub for non-Linux platforms.
type DnsBridge struct {
	SocketPath string
	DnsAddr    string
}

// ReverseBridge is a stub for non-Linux platforms.
type ReverseBridge struct {
	Ports       []int
	SocketPaths []string
}

// LinuxSandboxOptions is a stub for non-Linux platforms.
type LinuxSandboxOptions struct {
	UseLandlock   bool
	UseSeccomp    bool
	UseEBPF       bool
	Monitor       bool
	Debug         bool
	Learning      bool
	StraceLogPath string
}

// NewProxyBridge returns an error on non-Linux platforms.
func NewProxyBridge(proxyURL string, debug bool) (*ProxyBridge, error) {
	return nil, fmt.Errorf("proxy bridge not available on this platform")
}

// Cleanup is a no-op on non-Linux platforms.
func (b *ProxyBridge) Cleanup() {}

// NewDnsBridge returns an error on non-Linux platforms.
func NewDnsBridge(dnsAddr string, debug bool) (*DnsBridge, error) {
	return nil, fmt.Errorf("DNS bridge not available on this platform")
}

// Cleanup is a no-op on non-Linux platforms.
func (b *DnsBridge) Cleanup() {}

// NewReverseBridge returns an error on non-Linux platforms.
func NewReverseBridge(ports []int, debug bool) (*ReverseBridge, error) {
	return nil, fmt.Errorf("reverse bridge not available on this platform")
}

// Cleanup is a no-op on non-Linux platforms.
func (b *ReverseBridge) Cleanup() {}

// WrapCommandLinux returns an error on non-Linux platforms.
func WrapCommandLinux(cfg *config.Config, command string, proxyBridge *ProxyBridge, dnsBridge *DnsBridge, reverseBridge *ReverseBridge, tun2socksPath string, debug bool) (string, error) {
	return "", fmt.Errorf("Linux sandbox not available on this platform")
}

// WrapCommandLinuxWithOptions returns an error on non-Linux platforms.
func WrapCommandLinuxWithOptions(cfg *config.Config, command string, proxyBridge *ProxyBridge, dnsBridge *DnsBridge, reverseBridge *ReverseBridge, tun2socksPath string, opts LinuxSandboxOptions) (string, error) {
	return "", fmt.Errorf("Linux sandbox not available on this platform")
}

// StartLinuxMonitor returns nil on non-Linux platforms.
func StartLinuxMonitor(pid int, opts LinuxSandboxOptions) (*LinuxMonitors, error) {
	return nil, nil
}

// LinuxMonitors is a stub for non-Linux platforms.
type LinuxMonitors struct{}

// Stop is a no-op on non-Linux platforms.
func (m *LinuxMonitors) Stop() {}

// PrintLinuxFeatures prints a message on non-Linux platforms.
func PrintLinuxFeatures() {
	fmt.Println("Linux sandbox features are only available on Linux.")
}
