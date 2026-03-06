package sandbox

import (
	"encoding/base64"
	"os"
	"path/filepath"
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
func GenerateProxyEnvVars(proxyURL, httpProxyURL string) []string {
	envVars := []string{
		"GREYWALL_SANDBOX=1",
		"TMPDIR=/tmp/greywall",
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

	return envVars
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
