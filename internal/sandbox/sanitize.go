package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DangerousEnvPrefixes lists environment variable prefixes that can be used
// to subvert library loading and should be stripped from sandboxed processes.
//
// - LD_* (Linux): LD_PRELOAD, LD_LIBRARY_PATH can inject malicious shared libraries
// - DYLD_* (macOS): DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH can inject dylibs
var DangerousEnvPrefixes = []string{
	"LD_",   // Linux dynamic linker
	"DYLD_", // macOS dynamic linker
}

// DangerousEnvVars lists specific environment variables that should be stripped.
var DangerousEnvVars = []string{
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"LD_AUDIT",
	"LD_DEBUG",
	"LD_DEBUG_OUTPUT",
	"LD_DYNAMIC_WEAK",
	"LD_ORIGIN_PATH",
	"LD_PROFILE",
	"LD_PROFILE_OUTPUT",
	"LD_SHOW_AUXV",
	"LD_TRACE_LOADED_OBJECTS",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"DYLD_FRAMEWORK_PATH",
	"DYLD_FALLBACK_LIBRARY_PATH",
	"DYLD_FALLBACK_FRAMEWORK_PATH",
	"DYLD_IMAGE_SUFFIX",
	"DYLD_FORCE_FLAT_NAMESPACE",
	"DYLD_PRINT_LIBRARIES",
	"DYLD_PRINT_APIS",
}

// GetHardenedEnv returns a copy of the current environment with dangerous
// variables removed. This prevents library injection attacks where a malicious
// agent writes a .so/.dylib and then uses LD_PRELOAD/DYLD_INSERT_LIBRARIES
// in a subsequent command.
func GetHardenedEnv() []string {
	env := FilterDangerousEnv(os.Environ())
	if runtime.GOOS == "linux" {
		env = resolvePathInEnv(env)
	}
	return env
}

// resolvePathInEnv rewrites the PATH entry in env so that each directory is
// resolved to its real path via symlink evaluation. This is needed on NixOS
// where PATH contains /run/current-system/sw/bin (a symlink chain into
// /nix/store) which is unavailable inside the bwrap sandbox because /run is
// replaced with a tmpfs.
func resolvePathInEnv(env []string) []string {
	result := make([]string, len(env))
	for i, entry := range env {
		if !strings.HasPrefix(entry, "PATH=") {
			result[i] = entry
			continue
		}
		value := entry[len("PATH="):]
		dirs := strings.Split(value, string(filepath.ListSeparator))
		seen := make(map[string]bool, len(dirs))
		resolved := make([]string, 0, len(dirs))
		for _, d := range dirs {
			if d == "" {
				continue
			}
			if r, err := filepath.EvalSymlinks(d); err == nil {
				d = r
			}
			if !seen[d] {
				seen[d] = true
				resolved = append(resolved, d)
			}
		}
		result[i] = "PATH=" + strings.Join(resolved, string(filepath.ListSeparator))
	}
	return result
}

// FilterDangerousEnv filters out dangerous environment variables from the given slice.
func FilterDangerousEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if !isDangerousEnvVar(e) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// isDangerousEnvVar checks if an environment variable entry (KEY=VALUE) is dangerous.
func isDangerousEnvVar(entry string) bool {
	// Split on first '=' to get the key
	key := entry
	if idx := strings.Index(entry, "="); idx != -1 {
		key = entry[:idx]
	}

	// Check against known dangerous prefixes
	for _, prefix := range DangerousEnvPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}

	// Check against specific dangerous vars
	for _, dangerous := range DangerousEnvVars {
		if key == dangerous {
			return true
		}
	}

	return false
}

// GetStrippedEnvVars returns a list of environment variable names that were
// stripped from the given environment. Useful for debug logging.
func GetStrippedEnvVars(env []string) []string {
	var stripped []string
	for _, e := range env {
		if isDangerousEnvVar(e) {
			// Extract just the key
			if idx := strings.Index(e, "="); idx != -1 {
				stripped = append(stripped, e[:idx])
			} else {
				stripped = append(stripped, e)
			}
		}
	}
	return stripped
}

// HardeningFeatures returns a description of environment sanitization applied on this platform.
func HardeningFeatures() string {
	switch runtime.GOOS {
	case "linux":
		return "env-filter(LD_*)"
	case "darwin":
		return "env-filter(DYLD_*)"
	default:
		return "env-filter"
	}
}
