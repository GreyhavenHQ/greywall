//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanUseTransparentProxyRequiresChildNetworkAdministration(t *testing.T) {
	features := LinuxFeatures{
		HasIpCommand:  true,
		HasDevNetTun:  true,
		CanUnshareNet: true,
	}

	if features.CanUseTransparentProxy() {
		t.Fatal("transparent proxy must be disabled when the bwrap child lacks CAP_NET_ADMIN")
	}

	features.CanAdminNet = true
	if !features.CanUseTransparentProxy() {
		t.Fatal("transparent proxy should be enabled when all prerequisites are available")
	}
}

func TestDetectNetworkAdministrationProbesDisposableTun(t *testing.T) {
	binDir := t.TempDir()
	argsFile := filepath.Join(t.TempDir(), "bwrap-args")
	writeExecutable(t, filepath.Join(binDir, "ip"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(binDir, "bwrap"), "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$GREYWALL_TEST_ARGS\"\nexit 0\n")
	t.Setenv("PATH", binDir)
	t.Setenv("GREYWALL_TEST_ARGS", argsFile)

	features := LinuxFeatures{
		CanUnshareNet: true,
		HasIpCommand:  true,
		HasDevNetTun:  true,
	}
	features.detectNetworkAdministration()

	if !features.CanAdminNet {
		t.Fatal("expected successful child network administration probe")
	}
	data, err := os.ReadFile(argsFile) //nolint:gosec // path is created by this test
	if err != nil {
		t.Fatalf("read probe arguments: %v", err)
	}
	args := string(data)
	for _, expected := range []string{"--unshare-net", "--cap-add", "CAP_NET_ADMIN", "tuntap", "greywall-probe0", "tun"} {
		if !strings.Contains(args, expected+"\n") {
			t.Errorf("probe arguments do not contain %q:\n%s", expected, args)
		}
	}
}

func TestDetectNetworkAdministrationHandlesDeniedCapability(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "ip"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(binDir, "bwrap"), "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", binDir)

	features := LinuxFeatures{
		CanUnshareNet: true,
		HasIpCommand:  true,
		HasDevNetTun:  true,
	}
	features.detectNetworkAdministration()

	if features.CanAdminNet {
		t.Fatal("denied child network administration must disable transparent proxying")
	}
}

// TestDetectNetworkAdministrationSkipsWithoutPrerequisites verifies the probe
// returns early instead of shelling out when it cannot succeed. The stubbed
// bwrap on PATH reports success, so CanAdminNet becoming true would mean the
// guard was bypassed and the probe ran anyway.
func TestDetectNetworkAdministrationSkipsWithoutPrerequisites(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "ip"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(binDir, "bwrap"), "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", binDir)

	cases := map[string]LinuxFeatures{
		"no network namespace": {HasIpCommand: true, HasDevNetTun: true},
		"no ip command":        {CanUnshareNet: true, HasDevNetTun: true},
		"no /dev/net/tun":      {CanUnshareNet: true, HasIpCommand: true},
	}

	for name, features := range cases {
		t.Run(name, func(t *testing.T) {
			features.detectNetworkAdministration()
			if features.CanAdminNet {
				t.Errorf("probe executed despite %s", name)
			}
		})
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test executable: %v", err)
	}
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // test helper must create executable stubs
		t.Fatalf("make test executable runnable: %v", err)
	}
}
