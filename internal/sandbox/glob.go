package sandbox

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// ExpandGlobPatterns expands glob patterns to actual paths for sandbox rules
// (Landlock rules, bwrap binds, Seatbelt profiles).
// Optimized for Landlock's PATH_BENEATH semantics:
//   - "dir/**" → returns just "dir" (Landlock covers descendants automatically)
//   - "**/pattern" → scoped to cwd only, skips already-covered directories
//   - "**/dir/**" → finds dirs in cwd, returns them (PATH_BENEATH covers contents)
func ExpandGlobPatterns(patterns []string) []string {
	var expanded []string
	seen := make(map[string]bool)

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	// First pass: collect directories covered by "dir/**" patterns
	// These will be skipped when walking for "**/pattern" patterns
	coveredDirs := make(map[string]bool)
	for _, pattern := range patterns {
		if !ContainsGlobChars(pattern) {
			continue
		}
		pattern = NormalizePath(pattern)
		if strings.HasSuffix(pattern, "/**") && !strings.Contains(strings.TrimSuffix(pattern, "/**"), "**") {
			dir := strings.TrimSuffix(pattern, "/**")
			if !strings.HasPrefix(dir, "/") {
				dir = filepath.Join(cwd, dir)
			}
			// Store relative path for matching during walk
			relDir, err := filepath.Rel(cwd, dir)
			if err == nil {
				coveredDirs[relDir] = true
			}
		}
	}

	for _, pattern := range patterns {
		if !ContainsGlobChars(pattern) {
			// Not a glob, use as-is
			normalized := NormalizePath(pattern)
			if !seen[normalized] {
				seen[normalized] = true
				expanded = append(expanded, normalized)
			}
			continue
		}

		// Normalize pattern
		pattern = NormalizePath(pattern)

		// Case 1: "dir/**" - just return the dir (PATH_BENEATH handles descendants)
		// This avoids walking the directory entirely
		if strings.HasSuffix(pattern, "/**") && !strings.Contains(strings.TrimSuffix(pattern, "/**"), "**") {
			dir := strings.TrimSuffix(pattern, "/**")
			if !strings.HasPrefix(dir, "/") {
				dir = filepath.Join(cwd, dir)
			}
			if !seen[dir] {
				seen[dir] = true
				expanded = append(expanded, dir)
			}
			continue
		}

		// Case 2: "**/pattern" or "**/dir/**" - scope to cwd only
		// Skip directories already covered by dir/** patterns
		if strings.HasPrefix(pattern, "**/") {
			// Extract what we're looking for after the **/
			suffix := strings.TrimPrefix(pattern, "**/")

			// If it ends with /**, we're looking for directories
			isDir := strings.HasSuffix(suffix, "/**")
			if isDir {
				suffix = strings.TrimSuffix(suffix, "/**")
			}

			// Walk cwd looking for matches, skipping covered directories
			fsys := os.DirFS(cwd)
			searchPattern := "**/" + suffix

			err := doublestar.GlobWalk(fsys, searchPattern, func(path string, d fs.DirEntry) error {
				// Skip directories that are already covered by dir/** patterns
				// Check each parent directory of the current path
				pathParts := strings.Split(path, string(filepath.Separator))
				for i := 1; i <= len(pathParts); i++ {
					parentPath := strings.Join(pathParts[:i], string(filepath.Separator))
					if coveredDirs[parentPath] {
						if d.IsDir() {
							return fs.SkipDir
						}
						return nil // Skip this file, it's under a covered dir
					}
				}

				absPath := filepath.Join(cwd, path)
				if !seen[absPath] {
					seen[absPath] = true
					expanded = append(expanded, absPath)
				}
				return nil
			})
			if err != nil {
				continue
			}
			continue
		}

		// Case 3: Other patterns with * but not ** - use standard glob scoped to cwd
		if !strings.Contains(pattern, "**") {
			var searchBase string
			var searchPattern string

			if strings.HasPrefix(pattern, "/") {
				// Absolute pattern - find the non-glob prefix
				parts := strings.Split(pattern, "/")
				var baseparts []string
				for _, p := range parts {
					if ContainsGlobChars(p) {
						break
					}
					baseparts = append(baseparts, p)
				}
				searchBase = strings.Join(baseparts, "/")
				if searchBase == "" {
					searchBase = "/"
				}
				searchPattern = strings.TrimPrefix(pattern, searchBase+"/")
			} else {
				searchBase = cwd
				searchPattern = pattern
			}

			fsys := os.DirFS(searchBase)
			matches, err := doublestar.Glob(fsys, searchPattern)
			if err != nil {
				continue
			}

			for _, match := range matches {
				absPath := filepath.Join(searchBase, match)
				if !seen[absPath] {
					seen[absPath] = true
					expanded = append(expanded, absPath)
				}
			}
		}
	}

	return expanded
}
