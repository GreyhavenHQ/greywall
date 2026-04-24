package sandbox

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ContainsGlobChars checks if a path pattern contains glob characters.
func ContainsGlobChars(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[]")
}

// RemoveTrailingGlobSuffix removes trailing /** from a path pattern.
func RemoveTrailingGlobSuffix(pattern string) string {
	return strings.TrimSuffix(pattern, "/**")
}

// NormalizePath normalizes a path for sandbox configuration.
// Handles tilde expansion and relative paths.
func NormalizePath(pathPattern string) string {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	normalized := pathPattern

	// Expand ~ and relative paths
	switch {
	case pathPattern == "~":
		normalized = home
	case strings.HasPrefix(pathPattern, "~/"):
		normalized = filepath.Join(home, pathPattern[2:])
	case strings.HasPrefix(pathPattern, "./"), strings.HasPrefix(pathPattern, "../"):
		normalized, _ = filepath.Abs(filepath.Join(cwd, pathPattern))
	case !filepath.IsAbs(pathPattern) && !ContainsGlobChars(pathPattern):
		normalized, _ = filepath.Abs(filepath.Join(cwd, pathPattern))
	}

	// For non-glob patterns, try to resolve symlinks
	if !ContainsGlobChars(normalized) {
		if resolved, err := filepath.EvalSymlinks(normalized); err == nil {
			return resolved
		}
	}

	return normalized
}

// GenerateProxyEnvVars creates environment variables for proxy configuration.
// Used on macOS where transparent proxying is not available.
// proxyURL is the SOCKS5 proxy (for ALL_PROXY), httpProxyURL is the HTTP CONNECT proxy (for HTTP_PROXY/HTTPS_PROXY).
// tmpDir is the per-session temporary directory to expose as TMPDIR; if empty, TMPDIR is not overridden.
func GenerateProxyEnvVars(proxyURL, httpProxyURL, tmpDir string) []string {
	envVars := []string{"GREYWALL_SANDBOX=1"}
	if tmpDir != "" {
		envVars = append(envVars, "TMPDIR="+tmpDir)
	}

	if proxyURL == "" && httpProxyURL == "" {
		return envVars
	}

	// NO_PROXY for localhost and private networks
	noProxy := strings.Join([]string{
		"localhost",
		"127.0.0.1",
		"::1",
		"*.local",
		".local",
		"169.254.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}, ",")

	envVars = append(envVars,
		"NO_PROXY="+noProxy,
		"no_proxy="+noProxy,
	)

	// ALL_PROXY uses socks5h:// (remote DNS resolution via proxy)
	if proxyURL != "" {
		socksURL := strings.Replace(proxyURL, "socks5://", "socks5h://", 1)
		envVars = append(envVars,
			"ALL_PROXY="+socksURL,
			"all_proxy="+socksURL,
		)
	}

	// HTTP_PROXY/HTTPS_PROXY use the HTTP CONNECT proxy (not SOCKS5)
	if httpProxyURL != "" {
		envVars = append(envVars,
			"HTTP_PROXY="+httpProxyURL,
			"HTTPS_PROXY="+httpProxyURL,
			"http_proxy="+httpProxyURL,
			"https_proxy="+httpProxyURL,
		)
	}

	// Set CA cert env vars so sandboxed apps trust the greyproxy MITM CA certificate.
	// NODE_EXTRA_CA_CERTS: Node.js uses its own compiled-in CA bundle and ignores the OS keychain.
	// SSL_CERT_FILE: Used by OpenSSL-based tools (Python, Ruby, curl, wget, Go, etc.).
	// REQUESTS_CA_BUNDLE: Used by Python requests/httpx/aider and other Python HTTP clients.
	if certPath := greyproxyCACertPath(); certPath != "" {
		envVars = append(envVars, "NODE_EXTRA_CA_CERTS="+certPath)
		envVars = append(envVars, "SSL_CERT_FILE="+certPath)
		envVars = append(envVars, "REQUESTS_CA_BUNDLE="+certPath)
	}

	return envVars
}

// greyproxyCACertPath returns the path to the greyproxy CA certificate if it exists.
func greyproxyCACertPath() string {
	var dataHome string
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		dataHome = filepath.Join(home, "Library", "Application Support", "greyproxy")
	} else {
		// XDG_DATA_HOME or default
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			dataHome = filepath.Join(xdg, "greyproxy")
		} else {
			home, _ := os.UserHomeDir()
			dataHome = filepath.Join(home, ".local", "share", "greyproxy")
		}
	}
	certPath := filepath.Clean(filepath.Join(dataHome, "ca-cert.pem"))
	if _, err := os.Stat(certPath); err == nil { //nolint:gosec // path is constructed from trusted sources (home dir + constant)
		return certPath
	}
	return ""
}

// EncodeSandboxedCommand encodes a command for sandbox monitoring.
func EncodeSandboxedCommand(command string) string {
	if len(command) > 100 {
		command = command[:100]
	}
	return base64.StdEncoding.EncodeToString([]byte(command))
}

// DecodeSandboxedCommand decodes a base64-encoded command.
func DecodeSandboxedCommand(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
