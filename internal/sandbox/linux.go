//go:build linux

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gitea.app.monadical.io/monadical/greywall/internal/config"
)

// ProxyBridge bridges sandbox to an external SOCKS5 proxy via Unix socket.
type ProxyBridge struct {
	SocketPath string // Unix socket path
	ProxyHost  string // Parsed from ProxyURL
	ProxyPort  string // Parsed from ProxyURL
	ProxyUser  string // Username from ProxyURL (if any)
	ProxyPass  string // Password from ProxyURL (if any)
	HasAuth    bool   // Whether credentials were provided
	process    *exec.Cmd
	debug      bool
}

// DnsBridge bridges DNS queries from the sandbox to a host-side DNS server via Unix socket.
// Inside the sandbox, a socat relay converts UDP DNS queries (port 53) to the Unix socket.
// On the host, socat forwards from the Unix socket to the actual DNS server (UDP).
type DnsBridge struct {
	SocketPath string // Unix socket path
	DnsAddr    string // Host-side DNS address (host:port)
	process    *exec.Cmd
	debug      bool
}

// NewDnsBridge creates a Unix socket bridge to a host-side DNS server.
func NewDnsBridge(dnsAddr string, debug bool) (*DnsBridge, error) {
	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required for DNS bridge: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	socketPath := filepath.Join(tmpDir, fmt.Sprintf("greywall-dns-%s.sock", socketID))

	bridge := &DnsBridge{
		SocketPath: socketPath,
		DnsAddr:    dnsAddr,
		debug:      debug,
	}

	// Start bridge: Unix socket -> DNS server UDP
	socatArgs := []string{
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", socketPath),
		fmt.Sprintf("UDP:%s", dnsAddr),
	}
	bridge.process = exec.Command("socat", socatArgs...) //nolint:gosec // args constructed from trusted input
	if debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Starting DNS bridge: socat %s\n", strings.Join(socatArgs, " "))
	}
	if err := bridge.process.Start(); err != nil {
		return nil, fmt.Errorf("failed to start DNS bridge: %w", err)
	}

	// Wait for socket to be created
	for range 50 {
		if fileExists(socketPath) {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] DNS bridge ready (%s -> %s)\n", socketPath, dnsAddr)
			}
			return bridge, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	bridge.Cleanup()
	return nil, fmt.Errorf("timeout waiting for DNS bridge socket to be created")
}

// Cleanup stops the DNS bridge and removes the socket file.
func (b *DnsBridge) Cleanup() {
	if b.process != nil && b.process.Process != nil {
		_ = b.process.Process.Kill()
		_ = b.process.Wait()
	}
	_ = os.Remove(b.SocketPath)

	if b.debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] DNS bridge cleaned up\n")
	}
}

// ReverseBridge holds the socat bridge processes for inbound connections.
type ReverseBridge struct {
	Ports       []int
	SocketPaths []string // Unix socket paths for each port
	processes   []*exec.Cmd
	debug       bool
}

// LinuxSandboxOptions contains options for the Linux sandbox.
type LinuxSandboxOptions struct {
	// Enable Landlock filesystem restrictions (requires kernel 5.13+)
	UseLandlock bool
	// Enable seccomp syscall filtering
	UseSeccomp bool
	// Enable eBPF monitoring (requires CAP_BPF or root)
	UseEBPF bool
	// Enable violation monitoring
	Monitor bool
	// Debug mode
	Debug bool
	// Learning mode: permissive sandbox with strace tracing
	Learning bool
	// Path to host-side strace log file (bind-mounted into sandbox)
	StraceLogPath string
}

// NewProxyBridge creates a Unix socket bridge to an external SOCKS5 proxy.
// The bridge uses socat to forward from a Unix socket to the external proxy's TCP address.
func NewProxyBridge(proxyURL string, debug bool) (*ProxyBridge, error) {
	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required on Linux but not found: %w", err)
	}

	u, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	socketPath := filepath.Join(tmpDir, fmt.Sprintf("greywall-proxy-%s.sock", socketID))

	bridge := &ProxyBridge{
		SocketPath: socketPath,
		ProxyHost:  u.Hostname(),
		ProxyPort:  u.Port(),
		debug:      debug,
	}

	// Capture credentials from the proxy URL (if any)
	if u.User != nil {
		bridge.HasAuth = true
		bridge.ProxyUser = u.User.Username()
		bridge.ProxyPass, _ = u.User.Password()
	}

	// Start bridge: Unix socket -> external SOCKS5 proxy TCP
	socatArgs := []string{
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", socketPath),
		fmt.Sprintf("TCP:%s:%s", bridge.ProxyHost, bridge.ProxyPort),
	}
	bridge.process = exec.Command("socat", socatArgs...) //nolint:gosec // args constructed from trusted input
	if debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Starting proxy bridge: socat %s\n", strings.Join(socatArgs, " "))
	}
	if err := bridge.process.Start(); err != nil {
		return nil, fmt.Errorf("failed to start proxy bridge: %w", err)
	}

	// Wait for socket to be created, up to 5 seconds
	for range 50 {
		if fileExists(socketPath) {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] Proxy bridge ready (%s)\n", socketPath)
			}
			return bridge, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	bridge.Cleanup()
	return nil, fmt.Errorf("timeout waiting for proxy bridge socket to be created")
}

// Cleanup stops the bridge process and removes the socket file.
func (b *ProxyBridge) Cleanup() {
	if b.process != nil && b.process.Process != nil {
		_ = b.process.Process.Kill()
		_ = b.process.Wait()
	}
	_ = os.Remove(b.SocketPath)

	if b.debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Proxy bridge cleaned up\n")
	}
}

// parseProxyURL parses a SOCKS5 proxy URL and returns the parsed URL.
func parseProxyURL(proxyURL string) (*url.URL, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("proxy URL must use socks5:// or socks5h:// scheme, got %s", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, fmt.Errorf("proxy URL must include hostname and port")
	}
	return u, nil
}

// NewReverseBridge creates Unix socket bridges for inbound connections.
// Host listens on ports, forwards to Unix sockets that go into the sandbox.
func NewReverseBridge(ports []int, debug bool) (*ReverseBridge, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required on Linux but not found: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	bridge := &ReverseBridge{
		Ports: ports,
		debug: debug,
	}

	for _, port := range ports {
		socketPath := filepath.Join(tmpDir, fmt.Sprintf("greywall-rev-%d-%s.sock", port, socketID))
		bridge.SocketPaths = append(bridge.SocketPaths, socketPath)

		// Start reverse bridge: TCP listen on host port -> Unix socket
		// The sandbox will create the Unix socket with UNIX-LISTEN
		// We use retry to wait for the socket to be created by the sandbox
		args := []string{
			fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", port),
			fmt.Sprintf("UNIX-CONNECT:%s,retry=50,interval=0.1", socketPath),
		}
		proc := exec.Command("socat", args...) //nolint:gosec // args constructed from trusted input
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall:linux] Starting reverse bridge for port %d: socat %s\n", port, strings.Join(args, " "))
		}
		if err := proc.Start(); err != nil {
			bridge.Cleanup()
			return nil, fmt.Errorf("failed to start reverse bridge for port %d: %w", port, err)
		}
		bridge.processes = append(bridge.processes, proc)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Reverse bridges ready for ports: %v\n", ports)
	}

	return bridge, nil
}

// Cleanup stops the reverse bridge processes and removes socket files.
func (b *ReverseBridge) Cleanup() {
	for _, proc := range b.processes {
		if proc != nil && proc.Process != nil {
			_ = proc.Process.Kill()
			_ = proc.Wait()
		}
	}

	// Clean up socket files
	for _, socketPath := range b.SocketPaths {
		_ = os.Remove(socketPath)
	}

	if b.debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Reverse bridges cleaned up\n")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// isDirectory returns true if the path exists and is a directory.
func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// isSymlink returns true if the path is a symbolic link.
func isSymlink(path string) bool {
	info, err := os.Lstat(path) // Lstat doesn't follow symlinks
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}

// canMountOver returns true if bwrap can safely mount over this path.
// Returns false for symlinks (target may not exist in sandbox) and
// other special cases that could cause mount failures.
func canMountOver(path string) bool {
	if isSymlink(path) {
		return false
	}
	return fileExists(path)
}

// sameDevice returns true if both paths reside on the same filesystem (device).
func sameDevice(path1, path2 string) bool {
	var s1, s2 syscall.Stat_t
	if syscall.Stat(path1, &s1) != nil || syscall.Stat(path2, &s2) != nil {
		return true // err on the side of caution
	}
	return s1.Dev == s2.Dev
}

// intermediaryDirs returns the chain of directories between root and targetDir,
// from shallowest to deepest. Used to create --dir entries so bwrap can set up
// mount points inside otherwise-empty mount-point stubs.
//
// Example: intermediaryDirs("/", "/run/systemd/resolve") ->
//
//	["/run", "/run/systemd", "/run/systemd/resolve"]
func intermediaryDirs(root, targetDir string) []string {
	rel, err := filepath.Rel(root, targetDir)
	if err != nil {
		return []string{targetDir}
	}
	parts := strings.Split(rel, string(filepath.Separator))
	dirs := make([]string, 0, len(parts))
	current := root
	for _, part := range parts {
		current = filepath.Join(current, part)
		dirs = append(dirs, current)
	}
	return dirs
}

// getMandatoryDenyPaths returns concrete paths (not globs) that must be protected.
// This expands the glob patterns from GetMandatoryDenyPatterns into real paths.
func getMandatoryDenyPaths(cwd string) []string {
	var paths []string

	// Dangerous files in cwd
	for _, f := range DangerousFiles {
		p := filepath.Join(cwd, f)
		paths = append(paths, p)
	}

	// Dangerous directories in cwd
	for _, d := range DangerousDirectories {
		p := filepath.Join(cwd, d)
		paths = append(paths, p)
	}

	// Sensitive project files (e.g. .env) in cwd
	for _, f := range SensitiveProjectFiles {
		p := filepath.Join(cwd, f)
		paths = append(paths, p)
	}

	// Git hooks in cwd
	paths = append(paths, filepath.Join(cwd, ".git/hooks"))

	// Git config in cwd
	paths = append(paths, filepath.Join(cwd, ".git/config"))

	// Also protect home directory dangerous files
	home, err := os.UserHomeDir()
	if err == nil {
		for _, f := range DangerousFiles {
			p := filepath.Join(home, f)
			paths = append(paths, p)
		}
	}

	return paths
}

// buildDenyByDefaultMounts builds bwrap arguments for deny-by-default filesystem isolation.
// Starts with --tmpfs / (empty root), then selectively mounts system paths read-only,
// CWD read-write, and user tooling paths read-only. Sensitive files within CWD are masked.
func buildDenyByDefaultMounts(cfg *config.Config, cwd string, debug bool) []string {
	var args []string
	home, _ := os.UserHomeDir()

	// Start with empty root
	args = append(args, "--tmpfs", "/")

	// System paths (read-only) - on modern distros (Arch, Fedora, etc.),
	// /bin, /sbin, /lib, /lib64 are often symlinks to /usr/*. We must
	// recreate these as symlinks via --symlink so the dynamic linker
	// and shell can be found. Real directories get bind-mounted.
	systemPaths := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/run"}
	for _, p := range systemPaths {
		if !fileExists(p) {
			continue
		}
		if isSymlink(p) {
			// Recreate the symlink inside the sandbox (e.g., /bin -> usr/bin)
			target, err := os.Readlink(p)
			if err == nil {
				args = append(args, "--symlink", target, p)
			}
		} else {
			args = append(args, "--ro-bind", p, p)
		}
	}

	// /sys needs to be accessible for system info
	if fileExists("/sys") && canMountOver("/sys") {
		args = append(args, "--ro-bind", "/sys", "/sys")
	}

	// CWD: create intermediary dirs and bind read-write
	if cwd != "" && fileExists(cwd) {
		for _, dir := range intermediaryDirs("/", cwd) {
			// Skip dirs that are already mounted as system paths
			if isSystemMountPoint(dir) {
				continue
			}
			args = append(args, "--dir", dir)
		}
		args = append(args, "--bind", cwd, cwd)
	}

	// User tooling paths from GetDefaultReadablePaths() (read-only)
	// Filter out paths already mounted (system dirs, /dev, /proc, /tmp, macOS-specific)
	if home != "" {
		boundDirs := make(map[string]bool)
		for _, p := range GetDefaultReadablePaths() {
			// Skip system paths (already bound above), special mounts, and macOS paths
			if isSystemMountPoint(p) || p == "/dev" || p == "/proc" || p == "/sys" ||
				p == "/tmp" || p == "/private/tmp" ||
				strings.HasPrefix(p, "/System") || strings.HasPrefix(p, "/Library") ||
				strings.HasPrefix(p, "/Applications") || strings.HasPrefix(p, "/private/") ||
				strings.HasPrefix(p, "/nix") || strings.HasPrefix(p, "/snap") ||
				p == "/usr/local" || p == "/opt/homebrew" {
				continue
			}
			if !strings.HasPrefix(p, home) {
				continue // Only user tooling paths need intermediary dirs
			}
			if !fileExists(p) || !canMountOver(p) {
				continue
			}
			// Create intermediary dirs between root and this path
			for _, dir := range intermediaryDirs("/", p) {
				if !boundDirs[dir] && !isSystemMountPoint(dir) && dir != cwd {
					boundDirs[dir] = true
					args = append(args, "--dir", dir)
				}
			}
			args = append(args, "--ro-bind", p, p)
		}

		// Shell config files in home (read-only, literal files)
		shellConfigs := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".inputrc"}
		homeIntermedaryAdded := boundDirs[home]
		for _, f := range shellConfigs {
			p := filepath.Join(home, f)
			if fileExists(p) && canMountOver(p) {
				if !homeIntermedaryAdded {
					for _, dir := range intermediaryDirs("/", home) {
						if !boundDirs[dir] && !isSystemMountPoint(dir) {
							boundDirs[dir] = true
							args = append(args, "--dir", dir)
						}
					}
					homeIntermedaryAdded = true
				}
				args = append(args, "--ro-bind", p, p)
			}
		}

		// Home tool caches (read-only, for package managers/configs)
		homeCaches := []string{".cache", ".npm", ".cargo", ".rustup", ".local", ".config"}
		for _, d := range homeCaches {
			p := filepath.Join(home, d)
			if fileExists(p) && canMountOver(p) {
				if !homeIntermedaryAdded {
					for _, dir := range intermediaryDirs("/", home) {
						if !boundDirs[dir] && !isSystemMountPoint(dir) {
							boundDirs[dir] = true
							args = append(args, "--dir", dir)
						}
					}
					homeIntermedaryAdded = true
				}
				args = append(args, "--ro-bind", p, p)
			}
		}
	}

	// User-specified allowRead paths (read-only)
	if cfg != nil && cfg.Filesystem.AllowRead != nil {
		boundPaths := make(map[string]bool)

		expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowRead)
		for _, p := range expandedPaths {
			if fileExists(p) && canMountOver(p) &&
				!strings.HasPrefix(p, "/dev/") && !strings.HasPrefix(p, "/proc/") && !boundPaths[p] {
				boundPaths[p] = true
				// Create intermediary dirs if needed.
				// For files, only create dirs up to the parent to avoid
				// creating a directory at the file's path.
				dirTarget := p
				if !isDirectory(p) {
					dirTarget = filepath.Dir(p)
				}
				for _, dir := range intermediaryDirs("/", dirTarget) {
					if !isSystemMountPoint(dir) {
						args = append(args, "--dir", dir)
					}
				}
				args = append(args, "--ro-bind", p, p)
			}
		}
		for _, p := range cfg.Filesystem.AllowRead {
			normalized := NormalizePath(p)
			if !ContainsGlobChars(normalized) && fileExists(normalized) && canMountOver(normalized) &&
				!strings.HasPrefix(normalized, "/dev/") && !strings.HasPrefix(normalized, "/proc/") && !boundPaths[normalized] {
				boundPaths[normalized] = true
				dirTarget := normalized
				if !isDirectory(normalized) {
					dirTarget = filepath.Dir(normalized)
				}
				for _, dir := range intermediaryDirs("/", dirTarget) {
					if !isSystemMountPoint(dir) {
						args = append(args, "--dir", dir)
					}
				}
				args = append(args, "--ro-bind", normalized, normalized)
			}
		}
	}

	// Mask sensitive project files within CWD by overlaying an empty regular file.
	// We use an empty file instead of /dev/null because Landlock's READ_FILE right
	// doesn't cover character devices, causing "Permission denied" on /dev/null mounts.
	if cwd != "" {
		var emptyFile string
		for _, f := range SensitiveProjectFiles {
			p := filepath.Join(cwd, f)
			if fileExists(p) {
				if emptyFile == "" {
					emptyFile = filepath.Join(os.TempDir(), "greywall", "empty")
					_ = os.MkdirAll(filepath.Dir(emptyFile), 0o750)
					_ = os.WriteFile(emptyFile, nil, 0o444) //nolint:gosec // intentionally world-readable empty file for bind-mount masking
				}
				args = append(args, "--ro-bind", emptyFile, p)
				if debug {
					fmt.Fprintf(os.Stderr, "[greywall:linux] Masking sensitive file: %s\n", p)
				}
			}
		}
	}

	return args
}

// isSystemMountPoint returns true if the path is a top-level system directory
// that gets mounted directly under --tmpfs / (bwrap auto-creates these).
func isSystemMountPoint(path string) bool {
	switch path {
	case "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/run", "/sys",
		"/dev", "/proc", "/tmp",
		// macOS
		"/System", "/Library", "/Applications", "/private",
		// Package managers
		"/nix", "/snap", "/usr/local", "/opt/homebrew":
		return true
	}
	return false
}

// WrapCommandLinux wraps a command with Linux bubblewrap sandbox.
// It uses available security features (Landlock, seccomp) with graceful fallback.
func WrapCommandLinux(cfg *config.Config, command string, proxyBridge *ProxyBridge, dnsBridge *DnsBridge, reverseBridge *ReverseBridge, tun2socksPath string, debug bool) (string, error) {
	return WrapCommandLinuxWithOptions(cfg, command, proxyBridge, dnsBridge, reverseBridge, tun2socksPath, LinuxSandboxOptions{
		UseLandlock: true, // Enabled by default, will fall back if not available
		UseSeccomp:  true, // Enabled by default
		UseEBPF:     true, // Enabled by default if available
		Debug:       debug,
	})
}

// WrapCommandLinuxWithOptions wraps a command with configurable sandbox options.
func WrapCommandLinuxWithOptions(cfg *config.Config, command string, proxyBridge *ProxyBridge, dnsBridge *DnsBridge, reverseBridge *ReverseBridge, tun2socksPath string, opts LinuxSandboxOptions) (string, error) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return "", fmt.Errorf("bubblewrap (bwrap) is required on Linux but not found: %w", err)
	}

	shell := "bash"
	shellPath, err := exec.LookPath(shell)
	if err != nil {
		return "", fmt.Errorf("shell %q not found: %w", shell, err)
	}

	cwd, _ := os.Getwd()
	features := DetectLinuxFeatures()

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Available features: %s\n", features.Summary())
	}

	// Build bwrap args with filesystem restrictions
	bwrapArgs := []string{
		"bwrap",
	}
	// --new-session calls setsid() which detaches from the controlling terminal.
	// Skip it in learning mode so interactive programs (TUIs, prompts) can
	// read from /dev/tty. Learning mode already relaxes security constraints
	// (no seccomp, no landlock), so skipping new-session is acceptable.
	if !opts.Learning {
		bwrapArgs = append(bwrapArgs, "--new-session")
	}
	bwrapArgs = append(bwrapArgs, "--die-with-parent")

	// Always use --unshare-net when available (network namespace isolation)
	// Inside the namespace, tun2socks will provide transparent proxy access
	if features.CanUnshareNet {
		bwrapArgs = append(bwrapArgs, "--unshare-net") // Network namespace isolation
	} else if opts.Debug {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Skipping --unshare-net (network namespace unavailable in this environment)\n")
	}

	bwrapArgs = append(bwrapArgs, "--unshare-pid") // PID namespace isolation

	// Generate seccomp filter if available and requested
	var seccompFilterPath string
	if opts.UseSeccomp && features.HasSeccomp {
		filter := NewSeccompFilter(opts.Debug)
		filterPath, err := filter.GenerateBPFFilter()
		if err != nil {
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] Seccomp filter generation failed: %v\n", err)
			}
		} else {
			seccompFilterPath = filterPath
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] Seccomp filter enabled (blocking %d dangerous syscalls)\n", len(DangerousSyscalls))
			}
			// Add seccomp filter via fd 3 (will be set up via shell redirection)
			bwrapArgs = append(bwrapArgs, "--seccomp", "3")
		}
	}

	// Learning mode: permissive sandbox with home + cwd writable
	if opts.Learning {
		if opts.Debug {
			fmt.Fprintf(os.Stderr, "[greywall:linux] Learning mode: binding root read-only, home + cwd writable\n")
		}
		// Bind entire root read-only as baseline
		bwrapArgs = append(bwrapArgs, "--ro-bind", "/", "/")

		// Make home and cwd writable (overrides read-only)
		home, _ := os.UserHomeDir()
		if home != "" && fileExists(home) {
			bwrapArgs = append(bwrapArgs, "--bind", home, home)
		}
		if cwd != "" && fileExists(cwd) && cwd != home {
			bwrapArgs = append(bwrapArgs, "--bind", cwd, cwd)
		}

	}

	defaultDenyRead := cfg != nil && cfg.Filesystem.IsDefaultDenyRead()

	switch {
	case opts.Learning:
		// Skip defaultDenyRead logic in learning mode (already set up above)
	case defaultDenyRead:
		// Deny-by-default mode: start with empty root, then whitelist system paths + CWD
		if opts.Debug {
			fmt.Fprintf(os.Stderr, "[greywall:linux] DefaultDenyRead mode enabled - tmpfs root with selective mounts\n")
		}
		bwrapArgs = append(bwrapArgs, buildDenyByDefaultMounts(cfg, cwd, opts.Debug)...)
	default:
		// Legacy mode: bind entire root filesystem read-only
		bwrapArgs = append(bwrapArgs, "--ro-bind", "/", "/")
	}

	// Mount special filesystems
	// Use --dev-bind for /dev instead of --dev to preserve host device permissions
	// (the --dev minimal devtmpfs has permission issues when bwrap is setuid)
	bwrapArgs = append(bwrapArgs, "--dev-bind", "/dev", "/dev")
	bwrapArgs = append(bwrapArgs, "--proc", "/proc")

	// /tmp needs to be writable for many programs
	bwrapArgs = append(bwrapArgs, "--tmpfs", "/tmp")

	// Bind strace log file into sandbox AFTER --tmpfs /tmp so it's visible
	if opts.Learning && opts.StraceLogPath != "" {
		bwrapArgs = append(bwrapArgs, "--bind", opts.StraceLogPath, opts.StraceLogPath)
	}

	// Ensure /etc/resolv.conf is readable inside the sandbox.
	// On some systems (e.g., WSL), /etc/resolv.conf is a symlink to a path
	// on a separate mount point (e.g., /mnt/wsl/resolv.conf) that isn't
	// reachable after --ro-bind / / (non-recursive bind). When the target
	// is on a different filesystem, we create intermediate directories and
	// bind the real file at its original location so the symlink resolves.
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && target != "/etc/resolv.conf" {
		// Skip targets under specially-mounted dirs — a --tmpfs there would
		// overwrite the --dev-bind or --proc mounts established above.
		targetUnderSpecialMount := strings.HasPrefix(target, "/dev/") ||
			strings.HasPrefix(target, "/proc/") ||
			strings.HasPrefix(target, "/tmp/")
		// In defaultDenyRead mode, also skip if the target is under a path
		// already individually bound (e.g., /run, /sys) — a --tmpfs would
		// overwrite that explicit bind. Targets under unbound paths like
		// /mnt/wsl still need the fix.
		if defaultDenyRead {
			for _, p := range GetDefaultReadablePaths() {
				if strings.HasPrefix(target, p+"/") {
					targetUnderSpecialMount = true
					break
				}
			}
		}
		if fileExists(target) && !sameDevice("/", target) && !targetUnderSpecialMount {
			// Make the symlink target reachable by creating its parent dirs.
			// Walk down from / to the target's parent: skip dirs on the root
			// device (they have real content like /mnt/c, /mnt/d on WSL),
			// apply --tmpfs at the mount boundary (first dir on a different
			// device — an empty mount-point stub safe to replace), then --dir
			// for any deeper subdirectories inside the now-writable tmpfs.
			targetDir := filepath.Dir(target)
			mountBoundaryFound := false
			for _, dir := range intermediaryDirs("/", targetDir) {
				if !mountBoundaryFound {
					if !sameDevice("/", dir) {
						bwrapArgs = append(bwrapArgs, "--tmpfs", dir)
						mountBoundaryFound = true
					}
					// skip dirs still on root device
				} else {
					bwrapArgs = append(bwrapArgs, "--dir", dir)
				}
			}
			if mountBoundaryFound {
				bwrapArgs = append(bwrapArgs, "--ro-bind", target, target)
			}
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] Resolved /etc/resolv.conf symlink -> %s (cross-mount)\n", target)
			}
		}
	}

	// In learning mode, skip writable paths, deny rules, and mandatory deny
	// (the sandbox is already permissive with home + cwd writable)
	if !opts.Learning {

		writablePaths := make(map[string]bool)

		// Add default write paths (system paths needed for operation)
		for _, p := range GetDefaultWritePaths() {
			// Skip /dev paths (handled by --dev) and /tmp paths (handled by --tmpfs)
			if strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/private/tmp/") {
				continue
			}
			writablePaths[p] = true
		}

		// Add user-specified allowWrite paths
		if cfg != nil && cfg.Filesystem.AllowWrite != nil {
			expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowWrite)
			for _, p := range expandedPaths {
				writablePaths[p] = true
			}

			// Add non-glob paths
			for _, p := range cfg.Filesystem.AllowWrite {
				normalized := NormalizePath(p)
				if !ContainsGlobChars(normalized) {
					writablePaths[normalized] = true
				}
			}
		}

		// Make writable paths actually writable (override read-only root)
		for p := range writablePaths {
			if fileExists(p) {
				bwrapArgs = append(bwrapArgs, "--bind", p, p)
			}
		}

		// Handle denyRead paths - hide them
		// For directories: use --tmpfs to replace with empty tmpfs
		// For files: use --ro-bind /dev/null to mask with empty file
		// Skip symlinks: they may point outside the sandbox and cause mount errors
		if cfg != nil && cfg.Filesystem.DenyRead != nil {
			expandedDenyRead := ExpandGlobPatterns(cfg.Filesystem.DenyRead)
			for _, p := range expandedDenyRead {
				if canMountOver(p) {
					if isDirectory(p) {
						bwrapArgs = append(bwrapArgs, "--tmpfs", p)
					} else {
						// Mask file with /dev/null (appears as empty, unreadable)
						bwrapArgs = append(bwrapArgs, "--ro-bind", "/dev/null", p)
					}
				}
			}

			// Add non-glob paths
			for _, p := range cfg.Filesystem.DenyRead {
				normalized := NormalizePath(p)
				if !ContainsGlobChars(normalized) && canMountOver(normalized) {
					if isDirectory(normalized) {
						bwrapArgs = append(bwrapArgs, "--tmpfs", normalized)
					} else {
						bwrapArgs = append(bwrapArgs, "--ro-bind", "/dev/null", normalized)
					}
				}
			}
		}

		// Apply mandatory deny patterns (make dangerous files/dirs read-only)
		// This overrides any writable mounts for these paths
		//
		// Note: We only use concrete paths from getMandatoryDenyPaths(), NOT glob expansion.
		// GetMandatoryDenyPatterns() returns expensive **/pattern globs that require walking
		// the entire directory tree - this can hang on large directories (see issue #27).
		//
		// The concrete paths cover dangerous files in cwd and home directory. Files like
		// .bashrc in subdirectories are not protected, but this may be lower-risk since shell
		// rc files in project subdirectories are uncommon and not automatically sourced.
		//
		// TODO: consider depth-limited glob expansion (e.g., max 3 levels) to protect
		// subdirectory dangerous files without full tree walks that hang on large dirs.
		mandatoryDeny := getMandatoryDenyPaths(cwd)

		// In deny-by-default mode, sensitive project files are already masked
		// with --ro-bind /dev/null by buildDenyByDefaultMounts(). Skip them here
		// to avoid overriding the /dev/null mask with a real ro-bind.
		maskedPaths := make(map[string]bool)
		if defaultDenyRead {
			for _, f := range SensitiveProjectFiles {
				maskedPaths[filepath.Join(cwd, f)] = true
			}
		}

		// Deduplicate
		seen := make(map[string]bool)
		for _, p := range mandatoryDeny {
			if !seen[p] && fileExists(p) && !maskedPaths[p] {
				seen[p] = true
				bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
			}
		}

		// Handle explicit denyWrite paths (make them read-only)
		if cfg != nil && cfg.Filesystem.DenyWrite != nil {
			expandedDenyWrite := ExpandGlobPatterns(cfg.Filesystem.DenyWrite)
			for _, p := range expandedDenyWrite {
				if fileExists(p) && !seen[p] {
					seen[p] = true
					bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
				}
			}
			// Add non-glob paths
			for _, p := range cfg.Filesystem.DenyWrite {
				normalized := NormalizePath(p)
				if !ContainsGlobChars(normalized) && fileExists(normalized) && !seen[normalized] {
					seen[normalized] = true
					bwrapArgs = append(bwrapArgs, "--ro-bind", normalized, normalized)
				}
			}
		}

	} // end if !opts.Learning

	// Bind the proxy bridge Unix socket into the sandbox (needs to be writable)
	var dnsRelayResolvConf string // temp file path for custom resolv.conf
	if proxyBridge != nil {
		bwrapArgs = append(bwrapArgs,
			"--bind", proxyBridge.SocketPath, proxyBridge.SocketPath,
		)
		if tun2socksPath != "" && features.CanUseTransparentProxy() {
			// Bind /dev/net/tun for TUN device creation inside the sandbox
			if features.HasDevNetTun {
				bwrapArgs = append(bwrapArgs, "--dev-bind", "/dev/net/tun", "/dev/net/tun")
			}
			// Preserve CAP_NET_ADMIN (TUN device + network config) and
			// CAP_NET_BIND_SERVICE (DNS relay on port 53) inside the namespace
			bwrapArgs = append(bwrapArgs, "--cap-add", "CAP_NET_ADMIN")
			bwrapArgs = append(bwrapArgs, "--cap-add", "CAP_NET_BIND_SERVICE")
			// Bind the tun2socks binary into the sandbox (read-only)
			bwrapArgs = append(bwrapArgs, "--ro-bind", tun2socksPath, "/tmp/greywall-tun2socks")
		}

		// Bind DNS bridge socket if available
		if dnsBridge != nil {
			bwrapArgs = append(bwrapArgs,
				"--bind", dnsBridge.SocketPath, dnsBridge.SocketPath,
			)
		}

		// Override /etc/resolv.conf for DNS resolution inside the sandbox.
		if dnsBridge != nil || (tun2socksPath != "" && features.CanUseTransparentProxy()) {
			tmpResolv, err := os.CreateTemp("", "greywall-resolv-*.conf")
			if err == nil {
				if dnsBridge != nil {
					// DNS bridge: point at local socat relay (UDP :53 -> Unix socket -> host DNS server)
					_, _ = tmpResolv.WriteString("nameserver 127.0.0.1\n")
				} else {
					// tun2socks: point at public DNS with TCP mode.
					// tun2socks intercepts TCP traffic and forwards through the SOCKS5 proxy,
					// but doesn't reliably handle UDP DNS. "options use-vc" forces the resolver
					// to use TCP (RFC 1035 §4.2.2), which tun2socks handles natively.
					// Supported by glibc, Go 1.21+, c-ares, and most DNS resolver libraries.
					_, _ = tmpResolv.WriteString("nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions use-vc\n")
				}
				_ = tmpResolv.Close()
				dnsRelayResolvConf = tmpResolv.Name()
				bwrapArgs = append(bwrapArgs, "--ro-bind", dnsRelayResolvConf, "/etc/resolv.conf")
				if opts.Debug {
					if dnsBridge != nil {
						fmt.Fprintf(os.Stderr, "[greywall:linux] DNS: overriding resolv.conf -> 127.0.0.1 (bridge to %s)\n", dnsBridge.DnsAddr)
					} else {
						fmt.Fprintf(os.Stderr, "[greywall:linux] DNS: overriding resolv.conf -> 1.1.1.1 (TCP via tun2socks tunnel)\n")
					}
				}
			}
		}
	}

	// Bind reverse socket directory if needed (sockets created inside sandbox)
	if reverseBridge != nil && len(reverseBridge.SocketPaths) > 0 {
		// Get the temp directory containing the reverse sockets
		tmpDir := filepath.Dir(reverseBridge.SocketPaths[0])
		bwrapArgs = append(bwrapArgs, "--bind", tmpDir, tmpDir)
	}

	// Get greywall executable path for Landlock wrapper
	greywallExePath, _ := os.Executable()
	// Skip Landlock wrapper if executable is in /tmp (test binaries are built there)
	// The wrapper won't work because --tmpfs /tmp hides the test binary
	executableInTmp := strings.HasPrefix(greywallExePath, "/tmp/")
	// Skip Landlock wrapper if greywall is being used as a library (executable is not greywall)
	// The wrapper re-executes the binary with --landlock-apply, which only greywall understands
	executableIsGreywall := strings.Contains(filepath.Base(greywallExePath), "greywall")
	useLandlockWrapper := opts.UseLandlock && features.CanUseLandlock() && greywallExePath != "" && !executableInTmp && executableIsGreywall

	if opts.Debug && executableInTmp {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Skipping Landlock wrapper (executable in /tmp, likely a test)\n")
	}
	if opts.Debug && !executableIsGreywall {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Skipping Landlock wrapper (running as library, not greywall CLI)\n")
	}

	bwrapArgs = append(bwrapArgs, "--", shellPath, "-c")

	// Build the inner command that sets up tun2socks and runs the user command
	var innerScript strings.Builder

	innerScript.WriteString("export GREYWALL_SANDBOX=1\n")

	if proxyBridge != nil && tun2socksPath != "" && features.CanUseTransparentProxy() {
		// Build the tun2socks proxy URL with credentials if available
		// Many SOCKS5 proxies require the username/password auth flow even
		// without real credentials (e.g., gost always selects method 0x02).
		// Including userinfo ensures tun2socks offers both auth methods.
		tun2socksProxyURL := "socks5://127.0.0.1:${PROXY_PORT}"
		if proxyBridge.HasAuth {
			userinfo := url.UserPassword(proxyBridge.ProxyUser, proxyBridge.ProxyPass)
			tun2socksProxyURL = fmt.Sprintf("socks5://%s@127.0.0.1:${PROXY_PORT}", userinfo.String())
		}

		// Set up transparent proxy via TUN device + tun2socks
		innerScript.WriteString(fmt.Sprintf(`
# Bring up loopback interface (needed for socat to bind on 127.0.0.1)
ip link set lo up

# Set up TUN device for transparent proxying
ip tuntap add dev tun0 mode tun
ip addr add 198.18.0.1/15 dev tun0
ip link set dev tun0 up
ip route add default via 198.18.0.1 dev tun0

# Bridge: local port -> Unix socket -> host -> external SOCKS5 proxy
PROXY_PORT=18321
socat TCP-LISTEN:${PROXY_PORT},fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:%s >/dev/null 2>&1 &
BRIDGE_PID=$!

# Start tun2socks (transparent proxy via gvisor netstack)
/tmp/greywall-tun2socks -device tun0 -proxy %s >/dev/null 2>&1 &
TUN2SOCKS_PID=$!

`, proxyBridge.SocketPath, tun2socksProxyURL))

		// DNS relay: only needed when using a dedicated DNS bridge.
		// When using tun2socks without a DNS bridge, resolv.conf is configured with
		// "options use-vc" to force TCP DNS, which tun2socks handles natively.
		if dnsBridge != nil {
			// Dedicated DNS bridge: UDP :53 -> Unix socket -> host DNS server
			innerScript.WriteString(fmt.Sprintf(`# DNS relay: UDP queries -> Unix socket -> host DNS server (%s)
socat UDP4-RECVFROM:53,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &
DNS_RELAY_PID=$!

`, dnsBridge.DnsAddr, dnsBridge.SocketPath))
		}
	} else if proxyBridge != nil {
		// Fallback: no TUN support, use env-var-based proxying
		innerScript.WriteString(fmt.Sprintf(`
# Bring up loopback interface (needed for socat to bind on 127.0.0.1)
ip link set lo up 2>/dev/null

# Set up SOCKS5 bridge (no TUN available, env-var-based proxying)
PROXY_PORT=18321
socat TCP-LISTEN:${PROXY_PORT},fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:%s >/dev/null 2>&1 &
BRIDGE_PID=$!

export ALL_PROXY=socks5h://127.0.0.1:${PROXY_PORT}
export all_proxy=socks5h://127.0.0.1:${PROXY_PORT}
export HTTP_PROXY=socks5h://127.0.0.1:${PROXY_PORT}
export HTTPS_PROXY=socks5h://127.0.0.1:${PROXY_PORT}
export http_proxy=socks5h://127.0.0.1:${PROXY_PORT}
export https_proxy=socks5h://127.0.0.1:${PROXY_PORT}
export NO_PROXY=localhost,127.0.0.1
export no_proxy=localhost,127.0.0.1

`, proxyBridge.SocketPath))
	}

	// Set up reverse (inbound) socat listeners inside the sandbox
	if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
		innerScript.WriteString("\n# Start reverse bridge listeners for inbound connections\n")
		for i, port := range reverseBridge.Ports {
			socketPath := reverseBridge.SocketPaths[i]
			// Listen on Unix socket, forward to localhost:port inside the sandbox
			innerScript.WriteString(fmt.Sprintf(
				"socat UNIX-LISTEN:%s,fork,reuseaddr TCP:127.0.0.1:%d >/dev/null 2>&1 &\n",
				socketPath, port,
			))
			innerScript.WriteString(fmt.Sprintf("REV_%d_PID=$!\n", port))
		}
		innerScript.WriteString("\n")
	}

	// Add cleanup function
	innerScript.WriteString(`
# Cleanup function
cleanup() {
    jobs -p | xargs -r kill 2>/dev/null
}
trap cleanup EXIT

# Small delay to ensure services are ready
sleep 0.3

# Run the user command
`)

	// In learning mode, wrap the command with strace to trace syscalls.
	// Run strace in the foreground so the traced command retains terminal
	// access (stdin, /dev/tty) for interactive programs like TUIs.
	// If the app spawns long-lived child processes, strace -f may hang
	// after the main command exits; the user can Ctrl+C to stop it.
	// A SIGCHLD trap kills strace once its direct child exits, handling
	// the common case of background daemons (LSP servers, watchers).
	switch {
	case opts.Learning && opts.StraceLogPath != "":
		innerScript.WriteString(fmt.Sprintf(`# Learning mode: trace filesystem access (foreground for terminal access)
strace -f -qq -I2 -e trace=openat,open,creat,mkdir,mkdirat,unlinkat,renameat,renameat2,symlinkat,linkat -o %s -- %s
GREYWALL_STRACE_EXIT=$?
# Kill any orphaned child processes (LSP servers, file watchers, etc.)
# that were spawned by the traced command and reparented to PID 1.
kill -TERM -1 2>/dev/null
sleep 0.1
exit $GREYWALL_STRACE_EXIT
`,
			ShellQuoteSingle(opts.StraceLogPath), command,
		))
	case useLandlockWrapper:
		// Use Landlock wrapper if available
		// Pass config via environment variable (serialized as JSON)
		// This ensures allowWrite/denyWrite rules are properly applied
		if cfg != nil {
			configJSON, err := json.Marshal(cfg)
			if err == nil {
				innerScript.WriteString(fmt.Sprintf("export GREYWALL_CONFIG_JSON=%s\n", ShellQuoteSingle(string(configJSON))))
			}
		}

		// Build wrapper command with proper quoting
		// Use bash -c to preserve shell semantics (e.g., "echo hi && ls")
		wrapperArgs := []string{greywallExePath, "--landlock-apply"}
		if opts.Debug {
			wrapperArgs = append(wrapperArgs, "--debug")
		}
		wrapperArgs = append(wrapperArgs, "--", "bash", "-c", command)

		// Use exec to replace bash with the wrapper (which will exec the command)
		innerScript.WriteString(fmt.Sprintf("exec %s\n", ShellQuote(wrapperArgs)))
	default:
		innerScript.WriteString(command)
		innerScript.WriteString("\n")
	}

	bwrapArgs = append(bwrapArgs, innerScript.String())

	if opts.Debug {
		var featureList []string
		if features.CanUnshareNet {
			featureList = append(featureList, "bwrap(network,pid,fs)")
		} else {
			featureList = append(featureList, "bwrap(pid,fs)")
		}
		if proxyBridge != nil && features.CanUseTransparentProxy() {
			featureList = append(featureList, "tun2socks(transparent)")
		} else if proxyBridge != nil {
			featureList = append(featureList, "proxy(env-vars)")
		}
		if features.HasSeccomp && opts.UseSeccomp && seccompFilterPath != "" {
			featureList = append(featureList, "seccomp")
		}
		if useLandlockWrapper {
			featureList = append(featureList, fmt.Sprintf("landlock-v%d(wrapper)", features.LandlockABI))
		} else if features.CanUseLandlock() && opts.UseLandlock {
			featureList = append(featureList, fmt.Sprintf("landlock-v%d(unavailable)", features.LandlockABI))
		}
		if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
			featureList = append(featureList, fmt.Sprintf("inbound:%v", reverseBridge.Ports))
		}
		if opts.Learning {
			featureList = append(featureList, "learning(strace)")
		}
		fmt.Fprintf(os.Stderr, "[greywall:linux] Sandbox: %s\n", strings.Join(featureList, ", "))
	}

	// Build the final command
	bwrapCmd := ShellQuote(bwrapArgs)

	// If seccomp filter is enabled, wrap with fd redirection
	// bwrap --seccomp expects the filter on the specified fd
	if seccompFilterPath != "" {
		// Open filter file on fd 3, then run bwrap
		// The filter file will be cleaned up after the sandbox exits
		return fmt.Sprintf("exec 3<%s; %s", ShellQuoteSingle(seccompFilterPath), bwrapCmd), nil
	}

	return bwrapCmd, nil
}

// StartLinuxMonitor starts violation monitoring for a Linux sandbox.
// Returns monitors that should be stopped when the sandbox exits.
func StartLinuxMonitor(pid int, opts LinuxSandboxOptions) (*LinuxMonitors, error) {
	monitors := &LinuxMonitors{}
	features := DetectLinuxFeatures()

	// Note: SeccompMonitor is disabled because our seccomp filter uses SECCOMP_RET_ERRNO
	// which silently returns EPERM without logging to dmesg/audit.
	// To enable seccomp logging, the filter would need to use SECCOMP_RET_LOG (allows syscall)
	// or SECCOMP_RET_KILL (logs but kills process) or SECCOMP_RET_USER_NOTIF (complex).
	// For now, we rely on the eBPF monitor to detect syscall failures.
	if opts.Debug && opts.Monitor && features.SeccompLogLevel >= 1 {
		fmt.Fprintf(os.Stderr, "[greywall:linux] Note: seccomp violations are blocked but not logged (SECCOMP_RET_ERRNO is silent)\n")
	}

	// Start eBPF monitor if available and requested
	// This monitors syscalls that return EACCES/EPERM for sandbox descendants
	if opts.Monitor && opts.UseEBPF && features.HasEBPF {
		ebpfMon := NewEBPFMonitor(pid, opts.Debug)
		if err := ebpfMon.Start(); err != nil {
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] Failed to start eBPF monitor: %v\n", err)
			}
		} else {
			monitors.EBPFMonitor = ebpfMon
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[greywall:linux] eBPF monitor started for PID %d\n", pid)
			}
		}
	} else if opts.Monitor && opts.Debug {
		if !features.HasEBPF {
			fmt.Fprintf(os.Stderr, "[greywall:linux] eBPF monitoring not available (need CAP_BPF or root)\n")
		}
	}

	return monitors, nil
}

// LinuxMonitors holds all active monitors for a Linux sandbox.
type LinuxMonitors struct {
	EBPFMonitor *EBPFMonitor
}

// Stop stops all monitors.
func (m *LinuxMonitors) Stop() {
	if m.EBPFMonitor != nil {
		m.EBPFMonitor.Stop()
	}
}

// PrintLinuxFeatures prints available Linux sandbox features.
func PrintLinuxFeatures() {
	features := DetectLinuxFeatures()
	fmt.Printf("Linux Sandbox Features:\n")
	fmt.Printf("  Kernel: %d.%d\n", features.KernelMajor, features.KernelMinor)
	fmt.Printf("  Bubblewrap (bwrap): %v\n", features.HasBwrap)
	fmt.Printf("  Socat: %v\n", features.HasSocat)
	fmt.Printf("  Network namespace (--unshare-net): %v\n", features.CanUnshareNet)
	fmt.Printf("  Seccomp: %v (log level: %d)\n", features.HasSeccomp, features.SeccompLogLevel)
	fmt.Printf("  Landlock: %v (ABI v%d)\n", features.HasLandlock, features.LandlockABI)
	fmt.Printf("  eBPF: %v (CAP_BPF: %v, root: %v)\n", features.HasEBPF, features.HasCapBPF, features.HasCapRoot)
	fmt.Printf("  ip (iproute2): %v\n", features.HasIpCommand)
	fmt.Printf("  /dev/net/tun: %v\n", features.HasDevNetTun)
	fmt.Printf("  tun2socks: %v (embedded)\n", features.HasTun2Socks)

	fmt.Printf("\nFeature Status:\n")
	if features.MinimumViable() {
		fmt.Printf("  ✓ Minimum requirements met (bwrap + socat)\n")
	} else {
		fmt.Printf("  ✗ Missing requirements: ")
		if !features.HasBwrap {
			fmt.Printf("bwrap ")
		}
		if !features.HasSocat {
			fmt.Printf("socat ")
		}
		fmt.Println()
	}

	if features.CanUnshareNet {
		fmt.Printf("  ✓ Network namespace isolation available\n")
	} else if features.HasBwrap {
		fmt.Printf("  ⚠ Network namespace unavailable (containerized environment?)\n")
		fmt.Printf("    Sandbox will still work but with reduced network isolation.\n")
		fmt.Printf("    This is common in Docker, GitHub Actions, and other CI systems.\n")
	}

	if features.CanUseTransparentProxy() {
		fmt.Printf("  ✓ Transparent proxy available (tun2socks + TUN device)\n")
	} else {
		fmt.Printf("  ○ Transparent proxy not available (needs ip, /dev/net/tun, network namespace)\n")
	}

	if features.CanUseLandlock() {
		fmt.Printf("  ✓ Landlock available for enhanced filesystem control\n")
	} else {
		fmt.Printf("  ○ Landlock not available (kernel 5.13+ required)\n")
	}

	if features.CanMonitorViolations() {
		fmt.Printf("  ✓ Violation monitoring available\n")
	} else {
		fmt.Printf("  ○ Violation monitoring limited (kernel 4.14+ for seccomp logging)\n")
	}

	if features.HasEBPF {
		fmt.Printf("  ✓ eBPF monitoring available (enhanced visibility)\n")
	} else {
		fmt.Printf("  ○ eBPF monitoring not available (needs CAP_BPF or root)\n")
	}
}
