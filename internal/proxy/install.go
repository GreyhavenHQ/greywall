package proxy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	githubOwner = "greyhavenhq"
	githubRepo  = "greyproxy"
	apiTimeout  = 15 * time.Second
)

// release represents a GitHub release.
type release struct {
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

// asset represents a release asset.
type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// InstallOptions controls the greyproxy installation behavior.
type InstallOptions struct {
	Output io.Writer // progress output (typically os.Stderr)
	Tag    string    // specific tag to install; if empty, uses latest stable
	Beta   bool      // if Tag is empty and Beta is true, fetches latest pre-release tag
}

// CheckLatestVersion fetches the latest greyproxy release tag from GitHub
// and returns the version string (without the "v" prefix).
func CheckLatestVersion() (string, error) {
	rel, err := fetchLatestRelease()
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// IsOlderVersion returns true if current is strictly older than latest,
// or if current is not a valid semver string (e.g. "dev").
// Both strings should be in "major.minor.patch" format (no "v" prefix).
func IsOlderVersion(current, latest string) bool {
	cp := strings.SplitN(current, ".", 3)
	lp := strings.SplitN(latest, ".", 3)
	if len(lp) != 3 {
		return false
	}
	// If current is not valid semver (e.g. "dev"), treat as outdated.
	if len(cp) != 3 {
		return true
	}
	for i := 0; i < 3; i++ {
		c, err1 := strconv.Atoi(cp[i])
		l, err2 := strconv.Atoi(lp[i])
		if err1 != nil {
			return true
		}
		if err2 != nil {
			return false
		}
		if c < l {
			return true
		}
		if c > l {
			return false
		}
	}
	return false
}

// Install downloads the latest (or specified) greyproxy release and runs "greyproxy install".
// Set GREYWALL_NO_GREYPROXY_INSTALL=1 to skip installation entirely.
func Install(opts InstallOptions) error {
	if os.Getenv("GREYWALL_NO_GREYPROXY_INSTALL") == "1" {
		return nil
	}

	if opts.Output == nil {
		opts.Output = os.Stderr
	}

	// Resolve which tag to install
	var rel *release
	var err error
	switch {
	case opts.Tag != "":
		rel, err = fetchReleaseFor(nil, "", githubOwner, githubRepo, "tags/"+opts.Tag)
	case opts.Beta:
		tag, tagErr := fetchLatestPreReleaseTagFor(nil, "", githubOwner, githubRepo)
		if tagErr != nil {
			return fmt.Errorf("failed to fetch latest pre-release: %w", tagErr)
		}
		rel, err = fetchReleaseFor(nil, "", githubOwner, githubRepo, "tags/"+tag)
	default:
		rel, err = fetchLatestRelease()
	}
	if err != nil {
		return fmt.Errorf("failed to fetch release: %w", err)
	}

	_, _ = fmt.Fprintf(opts.Output, "Fetching greyproxy release %s...\n", rel.TagName)

	// Find the correct asset for this platform
	assetURL, assetName, err := resolveAssetURL(rel)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(opts.Output, "Downloading %s...\n", assetName)

	// Download to temp file
	archivePath, err := downloadAsset(assetURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = os.Remove(archivePath) }()

	// Extract
	_, _ = fmt.Fprintf(opts.Output, "Extracting...\n")
	extractDir, err := extractTarGz(archivePath)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	defer func() { _ = os.RemoveAll(extractDir) }()

	// Find the greyproxy binary in extracted content
	binaryPath := filepath.Join(extractDir, "greyproxy")
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("greyproxy binary not found in archive")
	}

	_, _ = fmt.Fprintf(opts.Output, "\n")
	if err := runGreyproxyInstall(binaryPath); err != nil {
		return fmt.Errorf("greyproxy install failed: %w", err)
	}

	_, _ = fmt.Fprintf(opts.Output, "\nVerifying installation...\n")
	status := Detect()
	if status.Installed {
		_, _ = fmt.Fprintf(opts.Output, "greyproxy %s installed at %s\n", status.Version, status.Path)
		if status.Running {
			_, _ = fmt.Fprintf(opts.Output, "greyproxy is running.\n")
		}
	} else {
		_, _ = fmt.Fprintf(opts.Output, "Warning: greyproxy not found on PATH after install.\n")
		_, _ = fmt.Fprintf(opts.Output, "Ensure ~/.local/bin is in your PATH.\n")
	}

	return nil
}

// DownloadGreywallBinary downloads the greywall release binary for the current platform
// to a temp directory and returns the path to the extracted binary.
// tag must include the "v" prefix (e.g. "v0.2.0").
// The caller is responsible for removing the returned directory when done.
func DownloadGreywallBinary(tag string) (binPath string, cleanup func(), err error) {
	rel, err := fetchReleaseFor(nil, "", "GreyhavenHQ", "greywall", "tags/"+tag)
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch greywall release %s: %w", tag, err)
	}

	downloadURL, _, err := resolveGreywallAssetURL(rel)
	if err != nil {
		return "", nil, err
	}

	archivePath, err := downloadAsset(downloadURL)
	if err != nil {
		return "", nil, fmt.Errorf("failed to download greywall %s: %w", tag, err)
	}

	extractDir, err := extractTarGz(archivePath)
	_ = os.Remove(archivePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to extract greywall archive: %w", err)
	}

	bin := filepath.Join(extractDir, "greywall")
	if _, err := os.Stat(bin); err != nil {
		_ = os.RemoveAll(extractDir)
		return "", nil, fmt.Errorf("greywall binary not found in archive")
	}

	return bin, func() { _ = os.RemoveAll(extractDir) }, nil
}

// CheckLatestTag returns the latest greyproxy release tag (with "v" prefix).
// If beta is true, returns the latest pre-release tag.
func CheckLatestTag(beta bool) (string, error) {
	return CheckLatestTagFor(githubOwner, githubRepo, beta)
}

// CheckLatestTagFor returns the latest release tag for any GitHub repo.
// If beta is true, returns the latest pre-release tag; otherwise returns the latest stable tag.
func CheckLatestTagFor(owner, repo string, beta bool) (string, error) {
	return checkLatestTagFor(nil, "", owner, repo, beta)
}

func checkLatestTagFor(client *http.Client, apiBase, owner, repo string, beta bool) (string, error) {
	if !beta {
		rel, err := fetchReleaseFor(client, apiBase, owner, repo, "latest")
		if err != nil {
			return "", err
		}
		return rel.TagName, nil
	}
	return fetchLatestPreReleaseTagFor(client, apiBase, owner, repo)
}

// fetchLatestRelease queries the GitHub API for the latest greyproxy release.
func fetchLatestRelease() (*release, error) {
	return fetchReleaseFor(nil, "", githubOwner, githubRepo, "latest")
}

// runGreyproxyInstall shells out to the extracted greyproxy binary with "install --force".
func runGreyproxyInstall(binaryPath string) error {
	cmd := exec.Command(binaryPath, "install", "--force") //nolint:gosec // binaryPath is from our extracted archive
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// resolveGreywallAssetURL finds the correct greywall asset URL for the current OS/arch.
// Greywall uses GoReleaser defaults: title-case OS (Darwin/Linux) and x86_64 for amd64.
func resolveGreywallAssetURL(rel *release) (downloadURL, name string, err error) {
	ver := strings.TrimPrefix(rel.TagName, "v")
	goos := runtime.GOOS
	osName := strings.ToUpper(goos[:1]) + goos[1:]
	archName := runtime.GOARCH
	switch archName {
	case "amd64":
		archName = "x86_64"
	case "386":
		archName = "i386"
	}

	expected := fmt.Sprintf("greywall_%s_%s_%s.tar.gz", ver, osName, archName)
	for _, a := range rel.Assets {
		if a.Name == expected {
			return a.BrowserDownloadURL, a.Name, nil
		}
	}
	return "", "", fmt.Errorf("no greywall asset found for %s/%s (expected: %s)", goos, runtime.GOARCH, expected)
}

// resolveAssetURL finds the correct asset download URL for the current OS/arch.
func resolveAssetURL(rel *release) (downloadURL, name string, err error) {
	ver := strings.TrimPrefix(rel.TagName, "v")
	osName := runtime.GOOS
	archName := runtime.GOARCH

	expected := fmt.Sprintf("greyproxy_%s_%s_%s.tar.gz", ver, osName, archName)

	for _, a := range rel.Assets {
		if a.Name == expected {
			return a.BrowserDownloadURL, a.Name, nil
		}
	}
	return "", "", fmt.Errorf("no release asset found for %s/%s (expected: %s)", osName, archName, expected)
}

// downloadAsset downloads a URL to a temp file, returning its path.
func downloadAsset(downloadURL string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req) //nolint:gosec // downloadURL comes from GitHub API response or hardcoded constants
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "greywall-download-*.tar.gz")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) //nolint:gosec // tmpFile.Name() is from os.CreateTemp, not user input
		return "", err
	}
	_ = tmpFile.Close()

	return tmpFile.Name(), nil
}

// extractTarGz extracts a .tar.gz archive to a temp directory, returning the dir path.
func extractTarGz(archivePath string) (string, error) {
	f, err := os.Open(archivePath) //nolint:gosec // archivePath is a temp file we created
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tmpDir, err := os.MkdirTemp("", "greywall-extract-*")
	if err != nil {
		return "", err
	}

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return "", fmt.Errorf("tar read error: %w", err)
		}

		// Sanitize: only extract regular files with safe names
		name := filepath.Base(header.Name)
		if name == "." || name == ".." || strings.Contains(header.Name, "..") {
			continue
		}

		target := filepath.Join(tmpDir, name) //nolint:gosec // name is sanitized via filepath.Base and path traversal check above

		switch header.Typeflag {
		case tar.TypeReg:
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)) //nolint:gosec // mode from tar header of trusted archive
			if err != nil {
				_ = os.RemoveAll(tmpDir)
				return "", err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, 256<<20)); err != nil { // 256 MB limit per file
				_ = out.Close()
				_ = os.RemoveAll(tmpDir)
				return "", err
			}
			_ = out.Close()
		}
	}

	return tmpDir, nil
}

// fetchReleaseFor fetches a specific GitHub release endpoint (e.g. "latest" or a tag name).
// client and apiBase are optional; nil/empty use production defaults.
func fetchReleaseFor(client *http.Client, apiBase, owner, repo, endpoint string) (*release, error) {
	if client == nil {
		client = &http.Client{Timeout: apiTimeout}
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases/%s", apiBase, owner, repo, endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "greywall-setup")

	resp, err := client.Do(req) //nolint:gosec // apiURL is built from controlled inputs
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to parse release response: %w", err)
	}
	return &rel, nil
}

// fetchLatestPreReleaseTagFor returns the most recent pre-release tag for the given repo.
// client and apiBase are optional; nil/empty use production defaults.
func fetchLatestPreReleaseTagFor(client *http.Client, apiBase, owner, repo string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: apiTimeout}
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=20", apiBase, owner, repo)

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "greywall-setup")

	resp, err := client.Do(req) //nolint:gosec // apiURL is built from controlled inputs
	if err != nil {
		return "", fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var releases []struct {
		TagName    string `json:"tag_name"`
		PreRelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to parse releases response: %w", err)
	}

	for _, r := range releases {
		if r.PreRelease {
			return r.TagName, nil
		}
	}
	return "", fmt.Errorf("no pre-release found for %s/%s", owner, repo)
}
