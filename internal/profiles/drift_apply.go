package profiles

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/sandbox"
)

// ApplyDriftAction executes the user's choice on a drifted learned profile.
//
//   - ActionSkip: no-op, returns learned unchanged. Re-prompts next run.
//   - ActionMerge: returns config.Merge(bundled, learned) and rewrites the
//     learned file on disk with the merged result, backing up the original to
//     <path>.bak. Merge is union-based so user customizations are preserved.
//   - ActionKeep: rewrites the learned file with the current drift hash
//     stamped so the prompt does not reappear until bundled changes to a
//     different delta. Backs up the original to <path>.bak.
//
// The returned *config.Config is the effective config to use for this run.
func ApplyDriftAction(action DriftAction, learned, bundled *config.Config, cmdName string) (*config.Config, error) {
	switch action {
	case ActionSkip:
		return learned, nil

	case ActionMerge:
		merged := config.Merge(bundled, learned)
		if err := rewriteLearnedFile(cmdName, merged); err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "[greywall:profile] Merged bundled %q into learned file (backup at %s.bak)\n",
			cmdName, sandbox.LearnedTemplatePath(cmdName))
		return merged, nil

	case ActionKeep:
		learned.DriftAckHash = DriftHash(learned, bundled)
		if err := rewriteLearnedFile(cmdName, learned); err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "[greywall:profile] Kept learned %q as-is; will not re-prompt until bundled profile changes again\n", cmdName)
		return learned, nil
	}
	return learned, nil
}

// rewriteLearnedFile writes cfg to the learned path for cmdName, backing up
// any existing file to <path>.bak. The saved file is stamped with the current
// schema version and greywall version.
func rewriteLearnedFile(cmdName string, cfg *config.Config) error {
	path := sandbox.LearnedTemplatePath(cmdName)

	// Back up existing file if present.
	if existing, err := os.ReadFile(path); err == nil { //nolint:gosec // learned path, user-owned
		backupPath := path + ".bak"
		if err := os.WriteFile(backupPath, existing, 0o600); err != nil { //nolint:gosec // derived from learned path, user-owned
			return fmt.Errorf("failed to write backup: %w", err)
		}
	}

	// Stamp with current schema + version.
	cfg.SchemaVersion = config.CurrentSchemaVersion
	cfg.GeneratedBy = sandbox.GreywallVersion()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	var content []byte
	content = fmt.Appendf(content, "// Learned profile for %q\n", cmdName)
	content = append(content, "// Updated by greywall after profile drift resolution\n"...)
	content = append(content, data...)
	content = append(content, '\n')

	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("failed to write learned profile: %w", err)
	}
	return nil
}
