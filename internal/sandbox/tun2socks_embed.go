//go:build linux

package sandbox

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

//go:embed bin/tun2socks-linux-*
var tun2socksFS embed.FS

// extractTun2Socks writes the embedded tun2socks binary to a temp file and returns its path.
// The caller is responsible for removing the file when done.
func extractTun2Socks() (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	default:
		return "", fmt.Errorf("tun2socks: unsupported architecture %s", runtime.GOARCH)
	}

	name := fmt.Sprintf("bin/tun2socks-linux-%s", arch)
	data, err := fs.ReadFile(tun2socksFS, name)
	if err != nil {
		return "", fmt.Errorf("tun2socks: embedded binary not found for %s: %w", arch, err)
	}

	tmpFile, err := os.CreateTemp("", "greywall-tun2socks-*")
	if err != nil {
		return "", fmt.Errorf("tun2socks: failed to create temp file: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("tun2socks: failed to write binary: %w", err)
	}
	_ = tmpFile.Close()

	if err := os.Chmod(tmpFile.Name(), 0o755); err != nil { //nolint:gosec // executable binary needs execute permission
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("tun2socks: failed to make executable: %w", err)
	}

	return tmpFile.Name(), nil
}
