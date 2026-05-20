//go:build !linux

package sandbox

// ApplySeccompFilter is a no-op on non-Linux platforms.
func ApplySeccompFilter(debug bool) error {
	return nil
}
