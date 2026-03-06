//go:build linux

package sandbox

import (
	"fmt"
	"os"
)

// generateLearnedTemplatePlatform parses the strace log and generates a template (Linux).
func (m *Manager) generateLearnedTemplatePlatform(cmdName string) (string, error) {
	if m.straceLogPath == "" {
		return "", fmt.Errorf("no strace log available (was learning mode enabled?)")
	}

	result, err := ParseStraceLog(m.straceLogPath, m.debug)
	if err != nil {
		return "", fmt.Errorf("failed to parse strace log: %w", err)
	}

	templatePath, err := GenerateLearnedTemplate(result, cmdName, m.debug)
	if err != nil {
		return "", err
	}

	// Clean up strace log since we've processed it
	_ = os.Remove(m.straceLogPath)
	m.straceLogPath = ""

	return templatePath, nil
}
