//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LinuxFeatures describes available Linux sandboxing features.
type LinuxFeatures struct {
	// Core dependencies
	HasBwrap bool
	HasSocat bool

	// Kernel features
	HasSeccomp      bool
	SeccompLogLevel int // 0=none, 1=LOG, 2=USER_NOTIF
	HasLandlock     bool
	LandlockABI     int // 0=none, 1-4 = ABI version

	// eBPF capabilities (requires CAP_BPF or root)
	HasEBPF    bool
	HasCapBPF  bool
	HasCapRoot bool

	// Network namespace capability
	// This can be false in containerized environments (Docker, CI) without CAP_NET_ADMIN
	CanUnshareNet bool

	// Transparent proxy support
	HasIpCommand bool // ip (iproute2) available
	HasDevNetTun bool // /dev/net/tun exists
	HasTun2Socks bool // tun2socks embedded binary available

	// Kernel version
	KernelMajor int
	KernelMinor int
}

var (
	detectedFeatures *LinuxFeatures
	detectOnce       sync.Once
)

// DetectLinuxFeatures checks what sandboxing features are available.
// Results are cached for subsequent calls.
func DetectLinuxFeatures() *LinuxFeatures {
	detectOnce.Do(func() {
		detectedFeatures = &LinuxFeatures{}
		detectedFeatures.detect()
	})
	return detectedFeatures
}

func (f *LinuxFeatures) detect() {
	// Check for bwrap and socat
	f.HasBwrap = commandExists("bwrap")
	f.HasSocat = commandExists("socat")

	// Parse kernel version
	f.parseKernelVersion()

	// Check seccomp support
	f.detectSeccomp()

	// Check Landlock support
	f.detectLandlock()

	// Check eBPF capabilities
	f.detectEBPF()

	// Check if we can create network namespaces
	f.detectNetworkNamespace()

	// Check transparent proxy support
	f.HasIpCommand = commandExists("ip")
	_, err := os.Stat("/dev/net/tun")
	f.HasDevNetTun = err == nil
	f.HasTun2Socks = true // embedded binary, always available
}

func (f *LinuxFeatures) parseKernelVersion() {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return
	}

	release := unix.ByteSliceToString(uname.Release[:])
	parts := strings.Split(release, ".")
	if len(parts) >= 2 {
		f.KernelMajor, _ = strconv.Atoi(parts[0])
		// Handle versions like "6.2.0-39-generic"
		minorStr := strings.Split(parts[1], "-")[0]
		f.KernelMinor, _ = strconv.Atoi(minorStr)
	}
}

func (f *LinuxFeatures) detectSeccomp() {
	// Check if seccomp is supported via prctl
	// PR_GET_SECCOMP returns 0 if seccomp is disabled, 1/2 if enabled, -1 on error
	_, _, err := unix.Syscall(unix.SYS_PRCTL, unix.PR_GET_SECCOMP, 0, 0)
	if err == 0 || err == unix.EINVAL {
		// EINVAL means seccomp is supported but not enabled for this process
		f.HasSeccomp = true
	}

	// SECCOMP_RET_LOG available since kernel 4.14
	if f.KernelMajor > 4 || (f.KernelMajor == 4 && f.KernelMinor >= 14) {
		f.SeccompLogLevel = 1
	}

	// SECCOMP_RET_USER_NOTIF available since kernel 5.0
	if f.KernelMajor >= 5 {
		f.SeccompLogLevel = 2
	}
}

func (f *LinuxFeatures) detectLandlock() {
	// Landlock available since kernel 5.13
	if f.KernelMajor < 5 || (f.KernelMajor == 5 && f.KernelMinor < 13) {
		return
	}

	// Try to query the Landlock ABI version using Landlock syscall
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
	// Returns the highest supported ABI version on success
	ret, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, // NULL attr to query ABI version
		0, // size = 0
		uintptr(LANDLOCK_CREATE_RULESET_VERSION),
	)

	// Check if syscall succeeded (errno == 0)
	// ret contains the ABI version number (1, 2, 3, 4, etc.)
	if err == 0 {
		f.HasLandlock = true
		f.LandlockABI = int(ret)
		return
	}

	// Fallback: try creating an actual ruleset (for older detection methods)
	attr := landlockRulesetAttr{
		handledAccessFS: LANDLOCK_ACCESS_FS_READ_FILE,
	}
	ret, _, err = unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), //nolint:gosec // required for syscall
		unsafe.Sizeof(attr),
		0,
	)
	if err == 0 {
		f.HasLandlock = true
		f.LandlockABI = 1 // Minimum supported version
		_ = unix.Close(int(ret))
	}
}

func (f *LinuxFeatures) detectEBPF() {
	// Check if we have CAP_BPF or CAP_SYS_ADMIN (root)
	f.HasCapRoot = os.Geteuid() == 0

	// Try to check CAP_BPF capability
	if f.HasCapRoot {
		f.HasCapBPF = true
		f.HasEBPF = true
		return
	}

	// Check if user has CAP_BPF via /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			// Parse effective capabilities
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				caps, err := strconv.ParseUint(fields[1], 16, 64)
				if err == nil {
					// CAP_BPF is bit 39
					const CAP_BPF = 39
					if caps&(1<<CAP_BPF) != 0 {
						f.HasCapBPF = true
						f.HasEBPF = true
					}
				}
			}
			break
		}
	}
}

// detectNetworkNamespace probes whether bwrap --unshare-net works.
// This can fail in containerized environments (Docker, GitHub Actions, etc.)
// that don't have CAP_NET_ADMIN capability needed to set up the loopback interface.
func (f *LinuxFeatures) detectNetworkNamespace() {
	if !f.HasBwrap {
		return
	}

	// Run a minimal bwrap command with --unshare-net to test if it works
	// We use a very short timeout since this should either succeed or fail immediately
	// The bind mount is required in some environments
	cmd := exec.Command("bwrap", "--unshare-net", "--ro-bind", "/", "/", "--", "/bin/true")
	err := cmd.Run()
	f.CanUnshareNet = err == nil
}

// Summary returns a human-readable summary of available features.
func (f *LinuxFeatures) Summary() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("kernel %d.%d", f.KernelMajor, f.KernelMinor))

	if f.HasBwrap {
		if f.CanUnshareNet {
			parts = append(parts, "bwrap")
		} else {
			parts = append(parts, "bwrap(no-netns)")
		}
	}
	if f.HasSeccomp {
		switch f.SeccompLogLevel {
		case 2:
			parts = append(parts, "seccomp+usernotif")
		case 1:
			parts = append(parts, "seccomp+log")
		default:
			parts = append(parts, "seccomp")
		}
	}
	if f.HasLandlock {
		parts = append(parts, fmt.Sprintf("landlock-v%d", f.LandlockABI))
	}
	if f.HasEBPF {
		if f.HasCapRoot {
			parts = append(parts, "ebpf(root)")
		} else {
			parts = append(parts, "ebpf(CAP_BPF)")
		}
	}

	return strings.Join(parts, ", ")
}

// CanMonitorViolations returns true if we can monitor sandbox violations.
func (f *LinuxFeatures) CanMonitorViolations() bool {
	// seccomp LOG requires kernel 4.14+
	// eBPF monitoring requires CAP_BPF or root
	return f.SeccompLogLevel >= 1 || f.HasEBPF
}

// CanUseLandlock returns true if Landlock is available.
func (f *LinuxFeatures) CanUseLandlock() bool {
	return f.HasLandlock && f.LandlockABI >= 1
}

// CanUseTransparentProxy returns true if transparent proxying via tun2socks is possible.
func (f *LinuxFeatures) CanUseTransparentProxy() bool {
	return f.HasIpCommand && f.HasDevNetTun && f.CanUnshareNet
}

// MinimumViable returns true if the minimum required features are available.
func (f *LinuxFeatures) MinimumViable() bool {
	return f.HasBwrap && f.HasSocat
}

// PrintDependencyStatus prints dependency status with install suggestions for Linux.
func PrintDependencyStatus() {
	features := DetectLinuxFeatures()

	fmt.Printf("\n  Platform: linux (kernel %d.%d)\n", features.KernelMajor, features.KernelMinor)

	fmt.Printf("\n  Dependencies (required):\n")

	allGood := true
	if features.HasBwrap {
		fmt.Printf("    ✓ bubblewrap (bwrap)\n")
	} else {
		fmt.Printf("    ✗ bubblewrap (bwrap) — REQUIRED\n")
		allGood = false
	}
	if features.HasSocat {
		fmt.Printf("    ✓ socat\n")
	} else {
		fmt.Printf("    ✗ socat — REQUIRED\n")
		allGood = false
	}

	if !allGood {
		fmt.Printf("\n  Install missing dependencies:\n")
		fmt.Printf("    %s\n", suggestInstallCmd(features))
	}

	fmt.Printf("\n  Security features: %s\n", features.Summary())

	if features.CanUseTransparentProxy() {
		fmt.Printf("  Transparent proxy: available\n")
	} else {
		parts := []string{}
		if !features.HasIpCommand {
			parts = append(parts, "iproute2")
		}
		if !features.HasDevNetTun {
			parts = append(parts, "/dev/net/tun")
		}
		if !features.CanUnshareNet {
			parts = append(parts, "network namespace")
		}
		if len(parts) > 0 {
			fmt.Printf("  Transparent proxy: unavailable (missing: %s)\n", strings.Join(parts, ", "))
		} else {
			fmt.Printf("  Transparent proxy: unavailable\n")
		}

		if !features.CanUnshareNet && features.HasBwrap {
			if val := readSysctl("kernel/apparmor_restrict_unprivileged_userns"); val == "1" {
				fmt.Printf("\n  Note: AppArmor is restricting unprivileged user namespaces.\n")
				fmt.Printf("  This prevents bwrap --unshare-net (needed for transparent proxy).\n")
				fmt.Printf("  To fix:  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n")
				fmt.Printf("  Persist: echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-greywall-userns.conf\n")
			}
		}
	}

	if allGood {
		fmt.Printf("\n  Status: ready\n")
	} else {
		fmt.Printf("\n  Status: missing required dependencies\n")
	}
}

func suggestInstallCmd(features *LinuxFeatures) string {
	var missing []string
	if !features.HasBwrap {
		missing = append(missing, "bubblewrap")
	}
	if !features.HasSocat {
		missing = append(missing, "socat")
	}
	pkgs := strings.Join(missing, " ")

	switch {
	case commandExists("apt-get"):
		return fmt.Sprintf("sudo apt install %s", pkgs)
	case commandExists("dnf"):
		return fmt.Sprintf("sudo dnf install %s", pkgs)
	case commandExists("yum"):
		return fmt.Sprintf("sudo yum install %s", pkgs)
	case commandExists("pacman"):
		return fmt.Sprintf("sudo pacman -S %s", pkgs)
	case commandExists("apk"):
		return fmt.Sprintf("sudo apk add %s", pkgs)
	case commandExists("zypper"):
		return fmt.Sprintf("sudo zypper install %s", pkgs)
	default:
		return fmt.Sprintf("install %s using your package manager", pkgs)
	}
}

func readSysctl(name string) string {
	data, err := os.ReadFile("/proc/sys/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Landlock constants
const (
	LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

	// Filesystem access rights (ABI v1+)
	LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
	LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
	LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
	LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
	LANDLOCK_ACCESS_FS_REMOVE_DIR  = 1 << 4
	LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
	LANDLOCK_ACCESS_FS_MAKE_CHAR   = 1 << 6
	LANDLOCK_ACCESS_FS_MAKE_DIR    = 1 << 7
	LANDLOCK_ACCESS_FS_MAKE_REG    = 1 << 8
	LANDLOCK_ACCESS_FS_MAKE_SOCK   = 1 << 9
	LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1 << 10
	LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 1 << 11
	LANDLOCK_ACCESS_FS_MAKE_SYM    = 1 << 12
	LANDLOCK_ACCESS_FS_REFER       = 1 << 13 // ABI v2
	LANDLOCK_ACCESS_FS_TRUNCATE    = 1 << 14 // ABI v3
	LANDLOCK_ACCESS_FS_IOCTL_DEV   = 1 << 15 // ABI v5

	// Network access rights (ABI v4+)
	LANDLOCK_ACCESS_NET_BIND_TCP    = 1 << 0
	LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

	// Rule types
	LANDLOCK_RULE_PATH_BENEATH = 1
	LANDLOCK_RULE_NET_PORT     = 2
)

// landlockRulesetAttr is the Landlock ruleset attribute structure
type landlockRulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64
}

// landlockPathBeneathAttr is used to add path-based rules
type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
	_             [4]byte // padding
}
