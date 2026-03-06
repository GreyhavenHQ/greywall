//go:build darwin

package sandbox

import (
	"fmt"
	"os"
)

// generateLearnedTemplatePlatform stops eslogger,
// parses the eslogger log with PID-based process tree filtering,
// and generates a template (macOS).
func (m *Manager) generateLearnedTemplatePlatform(cmdName string) (string, error) {
	if m.esloggerLogPath == "" {
		return "", fmt.Errorf("no eslogger log available (was learning mode enabled?)")
	}

	// Stop eslogger before parsing
	if m.esloggerCmd != nil && m.esloggerCmd.Process != nil {
		_ = m.esloggerCmd.Process.Signal(os.Interrupt)
		_ = m.esloggerCmd.Wait()
		m.esloggerCmd = nil
	}

	// Parse eslogger log with root PID for process tree tracking
	result, err := ParseEsloggerLog(m.esloggerLogPath, m.learningRootPID, m.debug)
	if err != nil {
		return "", fmt.Errorf("failed to parse eslogger log: %w", err)
	}

	templatePath, err := GenerateLearnedTemplate(result, cmdName, m.debug)
	if err != nil {
		return "", err
	}

	// Clean up eslogger log
	_ = os.Remove(m.esloggerLogPath)
	m.esloggerLogPath = ""

	return templatePath, nil
}
