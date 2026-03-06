//go:build !linux && !darwin

package sandbox

import "fmt"

// CheckLearningAvailable returns an error on unsupported platforms.
func CheckLearningAvailable() error {
	return fmt.Errorf("learning mode is only available on Linux (requires strace) and macOS (requires eslogger)")
}
