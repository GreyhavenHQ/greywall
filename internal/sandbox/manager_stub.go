//go:build !linux && !darwin

package sandbox

import "fmt"

// generateLearnedTemplatePlatform returns an error on unsupported platforms.
func (m *Manager) generateLearnedTemplatePlatform(cmdName string) (string, error) {
	return "", fmt.Errorf("learning mode is not supported on this platform")
}
