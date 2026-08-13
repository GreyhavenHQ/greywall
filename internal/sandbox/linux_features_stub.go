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
	CanAdminNet     bool
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

// PrintDependencyStatus prints dependency status for non-Linux platforms and returns remediation steps.
func PrintDependencyStatus() []string {
	if runtime.GOOS == "darwin" {
		fmt.Printf("Platform: macOS\n")
		fmt.Printf("\nChecking system capabilities:\n")
		if _, err := exec.LookPath("sandbox-exec"); err == nil {
			fmt.Println(CheckOK("sandbox-exec (Seatbelt)"))
		} else {
			fmt.Println(CheckFail("sandbox-exec — required (should be built-in on macOS)"))
			return []string{"Reinstall macOS Command Line Tools (sandbox-exec should be built-in)"}
		}
	} else {
		fmt.Printf("Platform: %s (unsupported)\n", runtime.GOOS)
	}
	return nil
}
