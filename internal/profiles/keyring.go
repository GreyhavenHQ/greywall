package profiles

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ResolveKeyringSecrets reads secrets from the host keyring and returns them
// as environment variable entries (KEY=VALUE). Only runs on Linux where
// secret-tool is available. Secrets are read before sandboxing so the
// D-Bus session bus (required by secret-tool) is still accessible.
//
// If an env var is already set in the environment, the keyring lookup is
// skipped for that variable (explicit env takes precedence).
func ResolveKeyringSecrets(secrets map[string]KeyringLookup, debug bool) []string {
	if len(secrets) == 0 || runtime.GOOS != "linux" {
		return nil
	}

	secretToolPath, err := exec.LookPath("secret-tool")
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall:keyring] secret-tool not found, skipping keyring injection\n")
		}
		return nil
	}

	var envVars []string
	for envName, lookup := range secrets {
		// Skip if already set in the environment
		if os.Getenv(envName) != "" {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:keyring] %s already set, skipping keyring lookup\n", envName)
			}
			continue
		}

		cmd := exec.Command(secretToolPath, "lookup", "service", lookup.Service) //nolint:gosec // args from trusted profile definitions
		out, err := cmd.Output()
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:keyring] Failed to read %s from keyring (service=%s): %v\n", envName, lookup.Service, err)
			}
			continue
		}

		token := strings.TrimSpace(string(out))
		if token == "" {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:keyring] Empty value for %s from keyring, skipping\n", envName)
			}
			continue
		}

		envVars = append(envVars, envName+"="+token)
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall:keyring] Injected %s from keyring (service=%s)\n", envName, lookup.Service)
		}
	}

	return envVars
}
