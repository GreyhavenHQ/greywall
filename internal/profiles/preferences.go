package profiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
)

// Preferences stores user preferences for the first-run UX.
type Preferences struct {
	SuppressProfilePrompt []string `json:"suppressProfilePrompt,omitempty"`
}

// preferencesPath returns the path to the preferences file.
func preferencesPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "greywall", "preferences.json")
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "greywall", "preferences.json")
	}
	return filepath.Join(configDir, "greywall", "preferences.json")
}

// LoadPreferences reads the preferences file. Returns empty preferences if the file doesn't exist.
func LoadPreferences() (*Preferences, error) {
	data, err := os.ReadFile(preferencesPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &Preferences{}, nil
		}
		return nil, err
	}
	var prefs Preferences
	if err := json.Unmarshal(data, &prefs); err != nil {
		return nil, err
	}
	return &prefs, nil
}

// SavePreferences writes the preferences file to disk.
func SavePreferences(prefs *Preferences) error {
	path := preferencesPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(prefs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// IsPromptSuppressed returns true if the user chose "never" for this command.
func (p *Preferences) IsPromptSuppressed(cmd string) bool {
	return slices.Contains(p.SuppressProfilePrompt, cmd)
}

// AddSuppression adds a command to the suppression list and saves.
func AddSuppression(cmd string) error {
	prefs, err := LoadPreferences()
	if err != nil {
		prefs = &Preferences{}
	}
	if !slices.Contains(prefs.SuppressProfilePrompt, cmd) {
		prefs.SuppressProfilePrompt = append(prefs.SuppressProfilePrompt, cmd)
	}
	return SavePreferences(prefs)
}
