//go:build !linux

package sandbox

import "fmt"

// StraceResult holds parsed read and write paths from an strace log.
type StraceResult struct {
	WritePaths []string
	ReadPaths  []string
}

// CheckStraceAvailable returns an error on non-Linux platforms.
func CheckStraceAvailable() error {
	return fmt.Errorf("learning mode is only available on Linux (requires strace and bubblewrap)")
}

// ParseStraceLog returns an error on non-Linux platforms.
func ParseStraceLog(logPath string, debug bool) (*StraceResult, error) {
	return nil, fmt.Errorf("strace log parsing is only available on Linux")
}
