//go:build !linux

package sandbox

import (
	"fmt"
	"os/exec"
	"runtime"
)

// LinuxFeatures describes available Linux sandboxing features.
// This is a stub for non-Linux platforms.
type LinuxFeatures struct {
	HasBwrap        bool
	HasSocat        bool
	HasSeccomp      bool
	SeccompLogLevel int
	HasLandlock     bool
	LandlockABI     int
	HasEBPF         bool
	HasCapBPF       bool
	HasCapRoot      bool
	CanUnshareNet   bool
	HasIpCommand    bool
	HasDevNetTun    bool
	HasTun2Socks    bool
	KernelMajor     int
	KernelMinor     int
}

// DetectLinuxFeatures returns empty features on non-Linux platforms.
func DetectLinuxFeatures() *LinuxFeatures {
	return &LinuxFeatures{}
}

// Summary returns an empty string on non-Linux platforms.
func (f *LinuxFeatures) Summary() string {
	return "not linux"
}

// CanMonitorViolations returns false on non-Linux platforms.
func (f *LinuxFeatures) CanMonitorViolations() bool {
	return false
}

// CanUseLandlock returns false on non-Linux platforms.
func (f *LinuxFeatures) CanUseLandlock() bool {
	return false
}

// CanUseTransparentProxy returns false on non-Linux platforms.
func (f *LinuxFeatures) CanUseTransparentProxy() bool {
	return false
}

// MinimumViable returns false on non-Linux platforms.
func (f *LinuxFeatures) MinimumViable() bool {
	return false
}

// PrintDependencyStatus prints dependency status for non-Linux platforms.
func PrintDependencyStatus() {
	if runtime.GOOS == "darwin" {
		fmt.Printf("\n  Platform: macOS\n")
		fmt.Printf("\n  Dependencies (required):\n")
		if _, err := exec.LookPath("sandbox-exec"); err == nil {
			fmt.Printf("    ✓ sandbox-exec (Seatbelt)\n")
			fmt.Printf("\n  Status: ready\n")
		} else {
			fmt.Printf("    ✗ sandbox-exec — REQUIRED (should be built-in on macOS)\n")
			fmt.Printf("\n  Status: missing required dependencies\n")
		}
	} else {
		fmt.Printf("\n  Platform: %s (unsupported)\n", runtime.GOOS)
		fmt.Printf("\n  Status: this platform is not supported\n")
	}
}
