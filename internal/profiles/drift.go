package profiles

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// driftDiffText returns the exact diff text that merging bundled into learned
// would produce. Used both for display and for acknowledgment hashing.
func driftDiffText(learned, bundled *config.Config) string {
	merged := config.Merge(bundled, learned)
	return DiffConfigs(learned, merged)
}

// DriftHash computes a stable hash of the drift delta between learned and
// bundled. Used to remember which delta the user has explicitly ignored so we
// don't re-prompt until the bundled profile drifts to a different delta.
func DriftHash(learned, bundled *config.Config) string {
	diff := driftDiffText(learned, bundled)
	if diff == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(diff))
	return hex.EncodeToString(sum[:16]) // 128 bits, plenty for dedup
}

// DriftReason describes why a learned profile is considered drifted relative
// to the current bundled profile.
type DriftReason string

const (
	// DriftNone means the learned profile is up-to-date with the running binary.
	DriftNone DriftReason = ""
	// DriftMissingStamp means the learned file has no schemaVersion stamp and
	// therefore predates versioned profile stamps.
	DriftMissingStamp DriftReason = "missing-stamp"
	// DriftSchema means the learned file has an older schemaVersion than the
	// running binary's CurrentSchemaVersion.
	DriftSchema DriftReason = "schema"
	// DriftVersion means the learned file's GeneratedBy differs from the
	// running greywall version.
	DriftVersion DriftReason = "version"
	// DriftContent means the bundled profile contains entries (network rules,
	// filesystem paths, etc.) that the learned file doesn't have. Authoritative
	// regardless of stamp: catches in-development "dev" builds where the
	// version string never changes but the rules do.
	DriftContent DriftReason = "content"
)

// DriftInfo describes the drift between a learned profile and the bundled one.
type DriftInfo struct {
	HasDrift       bool
	Reason         DriftReason
	LearnedVersion string // from file; empty if no stamp
	LearnedSchema  int    // from file; 0 if no stamp
	RunningVersion string // running greywall binary version
	RunningSchema  int    // CurrentSchemaVersion
	CmdName        string
}

// DetectDrift compares a loaded learned profile against the running binary's
// bundled profile for the same command. Returns drift info with HasDrift=true
// when the learned file appears out of date.
//
// Drift triggers when:
//   - the learned file has no schemaVersion stamp (predates versioning), OR
//   - the learned schemaVersion is older than CurrentSchemaVersion, OR
//   - the learned GeneratedBy differs from the running greywall version
//     AND a bundled profile exists for this command.
//
// A nil bundled argument means no bundled profile exists for the command; in
// that case we never report drift (nothing to update from).
func DetectDrift(learned, bundled *config.Config, runningVersion, cmdName string) DriftInfo {
	info := DriftInfo{
		CmdName:        cmdName,
		RunningVersion: runningVersion,
		RunningSchema:  config.CurrentSchemaVersion,
	}
	if learned == nil || bundled == nil {
		return info
	}
	info.LearnedSchema = learned.SchemaVersion
	info.LearnedVersion = learned.GeneratedBy

	// If the user previously ignored this exact delta, suppress drift
	// regardless of stamp state. The ack hash covers the concrete diff, so it
	// only lapses when bundled changes further.
	currentHash := DriftHash(learned, bundled)
	if currentHash != "" && learned.DriftAckHash == currentHash {
		return info
	}

	switch {
	case learned.SchemaVersion == 0:
		info.HasDrift = true
		info.Reason = DriftMissingStamp
	case learned.SchemaVersion < config.CurrentSchemaVersion:
		info.HasDrift = true
		info.Reason = DriftSchema
	case runningVersion != "" && learned.GeneratedBy != "" && learned.GeneratedBy != runningVersion:
		info.HasDrift = true
		info.Reason = DriftVersion
	case currentHash != "":
		// Stamps match but bundled has new entries the learned file doesn't.
		// Common during dev: version string is stable but rules changed.
		info.HasDrift = true
		info.Reason = DriftContent
	}
	return info
}
