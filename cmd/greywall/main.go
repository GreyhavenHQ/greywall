// Package main implements the greywall CLI.
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/platform"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
	_ "github.com/GreyhavenHQ/greywall/internal/profiles/agents"     // register built-in agent profiles
	_ "github.com/GreyhavenHQ/greywall/internal/profiles/toolchains" // register built-in toolchain profiles
	"github.com/GreyhavenHQ/greywall/internal/proxy"
	"github.com/GreyhavenHQ/greywall/internal/sandbox"
	"github.com/spf13/cobra"
)

// Build-time variables (set via -ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

var (
	debug                  bool
	monitor                bool
	settingsPath           string
	proxyURL               string
	httpProxyURL           string
	proxyUserFlag          string
	dnsAddr                string
	cmdString              string
	exposePorts            []string
	forwardPorts           []string
	exitCode               int
	showVersion            bool
	linuxFeatures          bool
	learning               bool
	profileName            string
	noNetworkRules         bool
	autoProfile            bool
	noCredentialProtection bool
	injectLabels           []string
	secretVars             []string
	ignoreVars             []string
	skipVersionCheck       bool
	allowDests             []string
	blankProfile           bool
	watch                  bool
)

func main() {
	// Check for internal --landlock-apply mode (used inside sandbox)
	// This must be checked before cobra to avoid flag conflicts
	if len(os.Args) >= 2 && os.Args[1] == "--landlock-apply" {
		runLandlockWrapper()
		return
	}

	// When invoked as "greywatch", inject --watch as the first flag so users get
	// observability-mode behaviour without needing to remember the flag.
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "greywatch" {
		os.Args = append([]string{os.Args[0], "--watch"}, os.Args[1:]...)
	}

	rootCmd := &cobra.Command{
		Use:   "greywall [flags] -- [command...]",
		Short: "Run commands in a sandbox with network and filesystem restrictions",
		Long: `greywall is a command-line tool that runs commands in a sandboxed environment
with network and filesystem restrictions.

By default, traffic is routed through the GreyProxy SOCKS5 proxy at localhost:43052
with DNS via localhost:43053. Use --proxy and --dns to override, or configure in
your settings file at ~/.config/greywall/greywall.json (or ~/Library/Application Support/greywall/greywall.json on macOS).

On Linux, greywall uses tun2socks for truly transparent proxying: all TCP/UDP traffic
from any binary is captured at the kernel level via a TUN device and forwarded
through the external SOCKS5 proxy. No application awareness needed.

On macOS, greywall uses sandbox-exec (Seatbelt) for filesystem/process isolation
and environment variables (HTTP_PROXY, ALL_PROXY) for network proxy routing.

Examples:
  greywall -- curl https://example.com                          # Blocked (no proxy)
  greywall --proxy socks5://localhost:1080 -- curl https://example.com  # Via proxy
  greywall -- curl -s https://example.com                       # Use -- to separate flags
  greywall -c "echo hello && ls"                                # Run with shell expansion
  greywall --settings config.json npm install
  greywall -p 3000 -c "npm run dev"                             # Expose port 3000
  greywall -f 5432 -- psql -h localhost                          # Forward host port into sandbox
  greywall --learning -- opencode                                # Learn filesystem needs
  greywall --secret MY_VAR -- command            # Protect a custom env var
  greywall --inject ANTHROPIC_API_KEY -- command  # Inject from proxy dashboard

Configuration file format:
{
  "network": {
    "proxyUrl": "socks5://localhost:1080"
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": []
  },
  "command": {
    "deny": ["git push", "npm publish"]
  },
  "allowAudio": true
}`,
		RunE:          runCommand,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
	}

	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.Flags().BoolVarP(&monitor, "monitor", "m", false, "Monitor and log sandbox violations")
	rootCmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "Path to settings file (default: OS config directory)")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "External SOCKS5 proxy URL (default: socks5://localhost:43052)")
	rootCmd.Flags().StringVar(&dnsAddr, "dns", "", "DNS server address on host (default: localhost:43053)")
	rootCmd.Flags().StringVar(&httpProxyURL, "http-proxy", "", "HTTP CONNECT proxy URL (default: http://localhost:43051)")
	rootCmd.Flags().StringVar(&proxyUserFlag, "proxy-user", "", "SOCKS5/HTTP proxy username to inject into the configured proxy URL (overrides any existing userinfo and the default auto-detected command name). Lets the upstream proxy match per-client rules by login.")
	rootCmd.Flags().StringVarP(&cmdString, "c", "c", "", "Run command string directly (like sh -c)")
	rootCmd.Flags().StringArrayVarP(&exposePorts, "port", "p", nil, "Expose port for inbound connections (can be used multiple times)")
	rootCmd.Flags().StringArrayVarP(&forwardPorts, "forward", "f", nil, "Forward host localhost port into sandbox (can be used multiple times)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information")
	rootCmd.Flags().BoolVar(&linuxFeatures, "linux-features", false, "Show available Linux security features and exit")
	rootCmd.Flags().BoolVar(&learning, "learning", false, "Run in learning mode: trace filesystem access and generate a config profile")
	rootCmd.Flags().StringVar(&profileName, "profile", "", "Load profiles by name, comma-separated (e.g. --profile claude,uv)")
	rootCmd.Flags().BoolVar(&noNetworkRules, "no-network-rules", false, "Skip applying profile network rules to greyproxy (filesystem + keyring still apply)")
	rootCmd.Flags().BoolVar(&autoProfile, "auto-profile", false, "Use saved or built-in profile without prompting")
	rootCmd.Flags().BoolVar(&noCredentialProtection, "no-credential-protection", false, "Disable credential substitution (real credentials visible in sandbox)")
	rootCmd.Flags().StringArrayVar(&injectLabels, "inject", nil, "Inject a global credential by label (can be used multiple times, e.g. --inject ANTHROPIC_API_KEY)")
	rootCmd.Flags().StringArrayVar(&secretVars, "secret", nil, "Protect an additional env var not in the default list (can be used multiple times)")
	rootCmd.Flags().StringArrayVar(&ignoreVars, "ignore-secret", nil, "Exclude an env var from credential detection (can be used multiple times)")
	rootCmd.Flags().BoolVar(&skipVersionCheck, "skip-version-check", false, "Skip greyproxy version check (for testing)")
	_ = rootCmd.Flags().MarkHidden("skip-version-check")
	rootCmd.Flags().StringArrayVar(&allowDests, "allow", nil, "Allow a network destination for this session (e.g. --allow api.example.com:443)")
	rootCmd.Flags().BoolVar(&blankProfile, "blank", false, "With --learning, skip default profile network rules (start from scratch)")
	rootCmd.Flags().BoolVar(&watch, "watch", false, "Watch mode: skip profile loading, allow all network (logged on dashboard), permissive filesystem — observability only, no deny-by-default")

	// Hidden aliases for backwards compatibility
	rootCmd.Flags().StringVar(&profileName, "template", "", "Alias for --profile (deprecated)")
	_ = rootCmd.Flags().MarkHidden("template")

	rootCmd.Flags().SetInterspersed(true)

	rootCmd.AddCommand(newCompletionCmd(rootCmd))
	rootCmd.AddCommand(newProfilesCmd())
	rootCmd.AddCommand(newCheckCmd())
	rootCmd.AddCommand(newSetupCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func runCommand(cmd *cobra.Command, args []string) error {
	// Record greywall version for profile stamping and drift detection.
	sandbox.SetGreywallVersion(version)

	if showVersion {
		fmt.Printf("greywall - lightweight, container-free sandbox for running untrusted commands\n")
		fmt.Printf("  Version: %s\n", version)
		fmt.Printf("  Built:   %s\n", buildTime)
		fmt.Printf("  Commit:  %s\n", gitCommit)
		sandbox.PrintDependencyStatus()
		return nil
	}

	if linuxFeatures {
		sandbox.PrintLinuxFeatures()
		return nil
	}

	var command string
	switch {
	case cmdString != "":
		command = cmdString
	case len(args) > 0:
		command = sandbox.ShellQuote(args)
	default:
		return fmt.Errorf("no command specified. Use -c <command> or provide command arguments")
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Command: %s\n", command)
	}

	var ports []int
	for _, p := range exposePorts {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, port)
	}

	if debug && len(ports) > 0 {
		fmt.Fprintf(os.Stderr, "[greywall] Exposing ports: %v\n", ports)
	}

	var fwdPorts []int
	for _, p := range forwardPorts {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid forward port: %s", p)
		}
		fwdPorts = append(fwdPorts, port)
	}

	if debug && len(fwdPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[greywall] Forwarding host ports: %v\n", fwdPorts)
	}

	// Load config: settings file > default path > default config
	var cfg *config.Config
	var err error

	switch {
	case settingsPath != "":
		cfg, err = config.Load(settingsPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	default:
		configPath := config.DefaultConfigPath()
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if cfg == nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall] No config found at %s, using default (block all network)\n", configPath)
			}
			cfg = config.Default()
		}
	}

	// Extract command name for profile lookup
	cmdName := extractCommandName(args, cmdString)

	// Load profiles. Watch mode never loads profiles — observability runs from a
	// blank default config so no per-tool rules influence what's observed.
	// In learning mode with --blank, skip profile loading entirely.
	// In learning mode without --blank, load profiles for network rules only.
	if !watch && (!learning || !blankProfile) {
		if profileName != "" {
			// Explicit --profile flag: resolve each comma-separated name
			names := strings.Split(profileName, ",")
			for _, name := range names {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				resolved, err := resolveProfile(name, debug)
				if err != nil {
					return err
				}
				if resolved != nil {
					cfg = config.Merge(cfg, resolved)
				}
			}
		} else if cmdName != "" {
			// Auto-detect by command name
			savedPath := sandbox.LearnedTemplatePath(cmdName)
			savedCfg, loadErr := config.Load(savedPath)
			switch {
			case loadErr != nil:
				if debug {
					fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to load saved profile: %v\n", loadErr)
				}
			case savedCfg != nil:
				savedCfg = maybeResolveDrift(savedCfg, cmdName)
				cfg = config.Merge(cfg, savedCfg)
				if debug {
					fmt.Fprintf(os.Stderr, "[greywall] Auto-loaded saved profile for %q\n", cmdName)
				}
			case autoProfile:
				// --auto-profile: silently apply built-in profile if available
				canonical := profiles.IsKnownAgent(cmdName)
				if canonical != "" {
					if profile := profiles.GetAgentProfile(canonical); profile != nil {
						if saveErr := profiles.SaveAsTemplate(profile, cmdName, debug); saveErr != nil && debug {
							fmt.Fprintf(os.Stderr, "[greywall] Warning: could not save profile: %v\n", saveErr)
						}
						cfg = config.Merge(cfg, profile)
						if debug {
							fmt.Fprintf(os.Stderr, "[greywall] Auto-applied built-in profile for %q\n", cmdName)
						}
					}
				}
			default:
				// No saved profile; try first-run UX for known agents
				profileCfg, profileErr := profiles.ResolveFirstRun(cmdName, false, debug)
				if profileErr != nil && debug {
					fmt.Fprintf(os.Stderr, "[greywall] Warning: first-run profile error: %v\n", profileErr)
				}
				if profileCfg != nil {
					cfg = config.Merge(cfg, profileCfg)
				}
			}
		}
	}

	// Merge config credentials with CLI flags (config + CLI, deduplicated)
	secretVars = mergeUnique(cfg.Credentials.Secrets, secretVars)
	injectLabels = mergeUnique(cfg.Credentials.Inject, injectLabels)
	ignoreVars = mergeUnique(cfg.Credentials.Ignore, ignoreVars)

	// CLI flags override config
	if proxyURL != "" {
		cfg.Network.ProxyURL = proxyURL
	}
	if httpProxyURL != "" {
		cfg.Network.HTTPProxyURL = httpProxyURL
	}
	if dnsAddr != "" {
		cfg.Network.DnsAddr = dnsAddr
	}

	// GreyProxy defaults: when no proxy or DNS is configured (neither via CLI
	// nor config file), use the standard GreyProxy ports.
	if cfg.Network.ProxyURL == "" {
		cfg.Network.ProxyURL = "socks5://localhost:43052"
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall] Defaulting proxy to socks5://localhost:43052\n")
		}
	}
	if cfg.Network.HTTPProxyURL == "" {
		cfg.Network.HTTPProxyURL = "http://localhost:43051"
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall] Defaulting HTTP proxy to http://localhost:43051\n")
		}
	}
	if cfg.Network.DnsAddr == "" {
		cfg.Network.DnsAddr = "localhost:43053"
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall] Defaulting DNS to localhost:43053\n")
		}
	}

	// Auto-inject proxy credentials so the proxy can identify the sandboxed command.
	// Precedence (highest wins):
	//   1. --proxy-user <name>   (explicit caller override, e.g. for per-agent
	//                             identity in a multi-tenant setup)
	//   2. cmdName               (auto-detected from the wrapped command)
	//   3. "proxy"               (fallback, required by gost for auth)
	// This always overrides any existing credentials in the URL.
	//
	// The same value is reused as the greyproxy session container name (see the
	// RegisterSession calls below). greyproxy associates a live proxy connection
	// with its session — and therefore enforces that session's network rules,
	// including --allow — by matching the SOCKS5 login against the container
	// name. The two MUST stay identical or session-scoped rules silently stop
	// applying (notably whenever --proxy-user is set).
	proxyUser := proxyIdentity(proxyUserFlag, cmdName)
	for _, proxyField := range []*string{&cfg.Network.ProxyURL, &cfg.Network.HTTPProxyURL} {
		if *proxyField != "" {
			if u, err := url.Parse(*proxyField); err == nil {
				u.User = url.UserPassword(proxyUser, "proxy")
				*proxyField = u.String()
			}
		}
	}
	if debug {
		source := "default"
		switch {
		case proxyUserFlag != "":
			source = "--proxy-user"
		case cmdName != "":
			source = "command name"
		}
		fmt.Fprintf(os.Stderr, "[greywall] Auto-set proxy credentials to %q:proxy (source: %s)\n", proxyUser, source)
	}

	// Merge CLI forward ports into config
	if len(fwdPorts) > 0 {
		cfg.Network.ForwardPorts = append(cfg.Network.ForwardPorts, fwdPorts...)
	}

	// Watch mode overrides: relax local enforcement so greywall acts as an
	// observability layer instead of a deny-by-default sandbox. Network is
	// permitted via a session-scoped */* allow rule registered with greyproxy
	// (see sessionNetworkRules below), so all traffic stays visible on the
	// dashboard while reaching its destination.
	if watch {
		falseVal := false
		cfg.Filesystem.DefaultDenyRead = &falseVal
		cfg.Filesystem.DenyRead = nil
		cfg.Filesystem.DenyWrite = nil
		if !slices.Contains(cfg.Filesystem.AllowWrite, "/") {
			cfg.Filesystem.AllowWrite = append(cfg.Filesystem.AllowWrite, "/")
		}
		cfg.Command.UseDefaults = &falseVal
		cfg.Command.Deny = nil
		fmt.Fprintf(os.Stderr, "[greywall] Watch mode: no profile, all network allowed (logged on dashboard), permissive filesystem\n")
	}

	// Learning mode setup
	if learning {
		if err := sandbox.CheckLearningAvailable(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[greywall] Learning mode: tracing filesystem access for %q\n", cmdName)
		fmt.Fprintf(os.Stderr, "[greywall] WARNING: The sandbox filesystem is relaxed during learning. Do not use for untrusted code.\n")
	}

	manager := sandbox.NewManager(cfg, debug, monitor)
	manager.SetExposedPorts(ports)
	if learning {
		manager.SetLearning(true)
		manager.SetCommandName(cmdName)
	}
	if watch {
		manager.SetWatch(true)
	}
	defer manager.Cleanup()

	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize sandbox: %w", err)
	}

	var logMonitor *sandbox.LogMonitor
	if monitor {
		logMonitor = sandbox.NewLogMonitor(sandbox.GetSessionSuffix())
		if logMonitor != nil {
			if err := logMonitor.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to start log monitor: %v\n", err)
			} else {
				defer logMonitor.Stop()
			}
		}
	}

	hardenedEnv := sandbox.GetHardenedEnv()
	if debug {
		if stripped := sandbox.GetStrippedEnvVars(os.Environ()); len(stripped) > 0 {
			fmt.Fprintf(os.Stderr, "[greywall] Stripped dangerous env vars: %v\n", stripped)
		}
	}

	// Check greyproxy version when --inject is used (requires global_credentials support)
	if len(injectLabels) > 0 && !skipVersionCheck {
		status := proxy.Detect()
		if !status.Running {
			return fmt.Errorf("--inject requires greyproxy to be running (run 'greywall setup')")
		}
		// global_credentials support was added after v0.3.3
		const minVersion = "0.3.4"
		if status.Version != "" && status.Version != "dev" && proxy.IsOlderVersion(status.Version, minVersion) {
			return fmt.Errorf("--inject requires greyproxy v%s or later (found v%s); upgrade with 'greywall setup'", minVersion, status.Version)
		}
	}

	// Build session network rules from profile config + --allow CLI flags.
	// --no-network-rules suppresses profile-sourced rules; CLI --allow still applies.
	var sessionNetworkRules []sandbox.NetworkRuleInput
	defaultNote := "greywall profile"
	if cmdName != "" {
		defaultNote = "greywall profile: " + cmdName
	}
	if noNetworkRules {
		if debug && len(cfg.Network.Rules) > 0 {
			fmt.Fprintf(os.Stderr, "[greywall] --no-network-rules: dropping %d profile rule(s)\n", len(cfg.Network.Rules))
		}
	} else {
		for _, r := range cfg.Network.Rules {
			port := r.Port
			if port == "" {
				port = "*"
			}
			action := r.Action
			if action == "" {
				action = "allow"
			}
			notes := r.Notes
			if notes == "" {
				notes = defaultNote
			}
			sessionNetworkRules = append(sessionNetworkRules, sandbox.NetworkRuleInput{
				DestinationPattern: r.Destination,
				PortPattern:        port,
				Action:             action,
				Notes:              notes,
			})
		}
	}
	for _, dest := range allowDests {
		// Parse "host:port" or just "host"
		host, port := dest, "*"
		if idx := strings.LastIndex(dest, ":"); idx > 0 {
			host = dest[:idx]
			port = dest[idx+1:]
		}
		sessionNetworkRules = append(sessionNetworkRules, sandbox.NetworkRuleInput{
			DestinationPattern: host,
			PortPattern:        port,
			Action:             "allow",
			Notes:              "CLI --allow flag",
		})
	}

	// Watch mode: register a single match-all allow rule on greyproxy so the
	// dashboard logs every request without blocking anything. Greyproxy's
	// pattern matcher treats "*" as match-all for both destination and port.
	if watch {
		sessionNetworkRules = append(sessionNetworkRules, sandbox.NetworkRuleInput{
			DestinationPattern: "*",
			PortPattern:        "*",
			Action:             "allow",
			Notes:              "greywatch: observe-only",
		})
	}

	sessionOpts := &sandbox.RegisterSessionOptions{
		NetworkRules: sessionNetworkRules,
		AllowAll:     learning,
	}

	// Credential substitution: detect credentials, rewrite .env files, register
	// with greyproxy, and substitute env vars. This must happen before WrapCommand
	// so that rewritten .env files are available for bind-mounting into the sandbox.
	var credSessionID string
	var credMappings []sandbox.CredentialMapping
	var rewrittenEnvFiles map[string]string
	var stopHeartbeat func()
	credSubstitutionActive := false
	if !noCredentialProtection && !learning {
		sessionID, err := sandbox.GenerateSessionID()
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall:cred] failed to generate session ID: %v\n", err)
			}
		} else {
			credSessionID = sessionID
			detected, err := sandbox.DetectCredentials(hardenedEnv, sessionID, secretVars, ignoreVars)
			if err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "[greywall:cred] failed to detect credentials: %v\n", err)
				}
			}
			if detected == nil {
				detected = []sandbox.CredentialMapping{}
			}

			// Must match the SOCKS5 login (proxyUser) so greyproxy maps this
			// session's network rules onto the sandbox's proxy connection.
			containerName := proxyUser

			if len(detected) > 0 || len(injectLabels) > 0 {
				// Build the set of credential key names for .env file scanning.
				credentialKeys := make(map[string]bool, len(detected)+len(injectLabels))
				for _, m := range detected {
					credentialKeys[m.EnvVar] = true
				}
				for _, label := range injectLabels {
					credentialKeys[label] = true
				}

				// Rewrite .env files BEFORE registration so file-specific
				// mappings can be included in the session.
				cwd, _ := os.Getwd()
				envResult, err := sandbox.RewriteEnvFiles(cwd, sessionID, credentialKeys, debug)
				if err != nil {
					if debug {
						fmt.Fprintf(os.Stderr, "[greywall:cred] failed to rewrite .env files: %v\n", err)
					}
				}

				// Combine env-detected mappings with file-specific mappings.
				allMappings := make([]sandbox.CredentialMapping, len(detected))
				copy(allMappings, detected)
				if envResult != nil {
					allMappings = append(allMappings, envResult.FileMappings...)
					rewrittenEnvFiles = envResult.RewrittenFiles
				}

				// Build metadata for the dashboard
				meta := &sandbox.SessionMetadata{
					WorkDir: cwd,
					Cmd:     cmdName,
					PID:     strconv.Itoa(os.Getpid()),
				}
				if len(args) > 0 {
					if binPath, err := exec.LookPath(args[0]); err == nil {
						meta.BinaryPath = binPath
					}
					if len(args) > 1 {
						meta.Args = strings.Join(args[1:], " ")
					}
				}

				// Register ALL mappings (env + file) with the proxy in one call.
				regResult, err := sandbox.RegisterSession(sessionID, containerName, allMappings, injectLabels, meta, "", sessionOpts)
				if err != nil {
					if debug {
						fmt.Fprintf(os.Stderr, "[greywall:cred] failed to register session: %v (credentials will be visible)\n", err)
					}
					// credMappings is still nil from declaration; nothing to clear.
					// Clean up rewritten files since we can't register them.
					sandbox.CleanupRewrittenFiles(rewrittenEnvFiles)
					rewrittenEnvFiles = nil
				} else {
					credMappings = allMappings

					// Add global credential mappings returned by the proxy.
					// Build envMappings (detected + globals) for env substitution
					// separately from credMappings (all) which includes file mappings.
					envMappings := make([]sandbox.CredentialMapping, len(detected))
					copy(envMappings, detected)
					for label, placeholder := range regResult.GlobalCredentials {
						m := sandbox.CredentialMapping{
							EnvVar:      label,
							Placeholder: placeholder,
						}
						credMappings = append(credMappings, m)
						envMappings = append(envMappings, m)
					}

					// Substitute credentials in the environment using only
					// env-detected + global mappings. File mappings must NOT
					// be used here because they may have different placeholders
					// for the same key name (e.g., .env has KEY=val1 while
					// the env var has KEY=val2).
					hardenedEnv = sandbox.SubstituteEnv(hardenedEnv, envMappings)
					stopHeartbeat = sandbox.StartHeartbeatLoop(sessionID, containerName, allMappings, injectLabels, meta, "", sessionOpts, debug)
					credSubstitutionActive = true
					manager.SetRewrittenEnvFiles(rewrittenEnvFiles)

					if debug {
						labels := make(map[string]bool)
						for _, m := range credMappings {
							labels[m.EnvVar] = true
						}
						var labelList []string
						for l := range labels {
							labelList = append(labelList, l)
						}
						fmt.Fprintf(os.Stderr, "[greywall:cred] protected %d credentials (%d env, %d from .env files): %s\n",
							len(credMappings), len(detected), len(credMappings)-len(detected), strings.Join(labelList, ", "))
					}
				}
			} else if debug {
				fmt.Fprintf(os.Stderr, "[greywall:cred] no credentials detected in environment\n")
			}
		}
	}

	// If we have network rules or allow_all but didn't register a session yet
	// (e.g., learning/watch mode, or no credentials detected), register a
	// session now. The credential block above may have generated a sessionID
	// without registering it (when no credentials were detected), so we gate
	// on credSubstitutionActive — which is the source of truth for whether
	// registration actually happened.
	if !credSubstitutionActive && (len(sessionNetworkRules) > 0 || learning) {
		sessionID, err := sandbox.GenerateSessionID()
		if err == nil {
			credSessionID = sessionID
			// Must match the SOCKS5 login (proxyUser) so greyproxy maps this
			// session's network rules onto the sandbox's proxy connection.
			containerName := proxyUser
			cwd, _ := os.Getwd()
			meta := &sandbox.SessionMetadata{
				WorkDir: cwd,
				Cmd:     cmdName,
				PID:     strconv.Itoa(os.Getpid()),
			}

			regResult, err := sandbox.RegisterSession(sessionID, containerName, nil, nil, meta, "", sessionOpts)
			if err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "[greywall] failed to register network rules session: %v\n", err)
				}
			} else {
				if regResult.RulesCreated > 0 && debug {
					fmt.Fprintf(os.Stderr, "[greywall] Network rules applied: %d rules from profile\n", regResult.RulesCreated)
				}
				if learning {
					fmt.Fprintf(os.Stderr, "[greywall] Learning mode: all network traffic allowed for this session\n")
				}
				stopHeartbeat = sandbox.StartHeartbeatLoop(sessionID, containerName, nil, nil, meta, "", sessionOpts, debug)
			}
		}
	} else if credSubstitutionActive && len(sessionNetworkRules) > 0 {
		// Session was already registered with credentials; log rule count.
		ruleCount := 0
		for range sessionNetworkRules {
			ruleCount++
		}
		if ruleCount > 0 && debug {
			fmt.Fprintf(os.Stderr, "[greywall] Network rules applied: %d rules from profile\n", ruleCount)
		}
	}

	// Warn if .env files will be masked because credential substitution is not active.
	if !credSubstitutionActive && !learning {
		cwd, _ := os.Getwd()
		sandbox.WarnMaskedEnvFiles(cwd)
	}

	// Ensure cleanup on exit
	defer func() {
		if stopHeartbeat != nil {
			stopHeartbeat()
		}
		if credSessionID != "" {
			_ = sandbox.DeleteSession(credSessionID, "")
		}
		sandbox.CleanupRewrittenFiles(rewrittenEnvFiles)
	}()

	sandboxedCommand, err := manager.WrapCommand(command)
	if err != nil {
		return fmt.Errorf("failed to wrap command: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Sandboxed command: %s\n", sandboxedCommand)
		fmt.Fprintf(os.Stderr, "[greywall] Executing: sh -c %q\n", sandboxedCommand)
	}

	// Inject keyring secrets for active profiles (Linux only).
	// This reads from the host keyring before sandboxing blocks D-Bus access.
	// Check the command itself and any explicitly loaded profiles.
	if !learning {
		profileNames := []string{cmdName}
		if profileName != "" {
			for _, name := range strings.Split(profileName, ",") {
				name = strings.TrimSpace(name)
				if name != "" {
					profileNames = append(profileNames, name)
				}
			}
		}
		for _, name := range profileNames {
			canonical := profiles.IsKnownAgent(name)
			if canonical == "" {
				continue
			}
			if secrets := profiles.GetKeyringSecrets(canonical); secrets != nil {
				hardenedEnv = append(hardenedEnv, profiles.ResolveKeyringSecrets(secrets, debug)...)
			}
		}
	}

	execCmd := exec.Command("sh", "-c", sandboxedCommand) //nolint:gosec // sandboxedCommand is constructed from user input - intentional
	execCmd.Env = hardenedEnv
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGWINCH, syscall.SIGUSR1, syscall.SIGUSR2)

	// Start the command (non-blocking) so we can get the PID
	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Record root PID for macOS learning mode (eslogger uses this for process tree tracking)
	if learning && platform.Detect() == platform.MacOS && execCmd.Process != nil {
		manager.SetLearningRootPID(execCmd.Process.Pid)
	}

	// Start Linux monitors (eBPF tracing for filesystem violations)
	var linuxMonitors *sandbox.LinuxMonitors
	if monitor && execCmd.Process != nil {
		linuxMonitors, _ = sandbox.StartLinuxMonitor(execCmd.Process.Pid, sandbox.LinuxSandboxOptions{
			Monitor: true,
			Debug:   debug,
			UseEBPF: true,
		})
		if linuxMonitors != nil {
			defer linuxMonitors.Stop()
		}
	}

	go func() {
		termCount := 0
		for sig := range sigChan {
			if execCmd.Process == nil {
				continue
			}
			// For termination signals, force kill on the second attempt
			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				termCount++
				if termCount >= 2 {
					_ = execCmd.Process.Kill()
					continue
				}
			}
			_ = execCmd.Process.Signal(sig)
		}
	}()

	// Wait for command to finish
	commandFailed := false
	if err := execCmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Set exit code but don't os.Exit() here - let deferred cleanup run
			exitCode = exitErr.ExitCode()
			commandFailed = true
		} else {
			return fmt.Errorf("command failed: %w", err)
		}
	}

	// Generate learned profile after command completes successfully.
	// Skip profile generation if the command failed — the strace trace
	// is likely incomplete and would produce an unreliable profile.
	if learning && manager.IsLearning() {
		if commandFailed {
			fmt.Fprintf(os.Stderr, "[greywall] Skipping profile generation: command exited with code %d\n", exitCode)
		} else {
			fmt.Fprintf(os.Stderr, "[greywall] Analyzing filesystem access patterns...\n")
			profilePath, genErr := manager.GenerateLearnedTemplate(cmdName)
			if genErr != nil {
				fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to generate profile: %v\n", genErr)
			} else {
				fmt.Fprintf(os.Stderr, "[greywall] Profile saved to: %s\n", profilePath)
				fmt.Fprintf(os.Stderr, "[greywall] Next run will auto-load this profile.\n")
			}
		}
	}

	return nil
}

// resolveProfile resolves a single profile name to a config.
// It tries a saved profile first, then falls back to a built-in profile.
// Returns an error if the name can't be resolved at all.
// maybeResolveDrift detects whether savedCfg is drifted from the bundled
// profile for the given name and, if so, prompts the user (TTY only) and
// applies their choice. Returns the effective config to use.
func maybeResolveDrift(savedCfg *config.Config, name string) *config.Config {
	canonical := profiles.IsKnownAgent(name)
	if canonical == "" {
		return savedCfg
	}
	bundled := profiles.GetAgentProfile(canonical)
	if bundled == nil {
		return savedCfg
	}
	drift := profiles.DetectDrift(savedCfg, bundled, version, name)
	if !drift.HasDrift {
		return savedCfg
	}
	action := profiles.PromptDriftResolution(drift, savedCfg, bundled)
	resolved, err := profiles.ApplyDriftAction(action, savedCfg, bundled, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to apply drift action: %v\n", err)
		return savedCfg
	}
	if resolved == nil {
		return savedCfg
	}
	return resolved
}

func resolveProfile(name string, debug bool) (*config.Config, error) {
	// Try saved profile first
	savedPath := sandbox.LearnedTemplatePath(name)
	savedCfg, loadErr := config.Load(savedPath)
	if loadErr != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to load saved profile %q: %v\n", name, loadErr)
		}
	}
	if savedCfg != nil {
		savedCfg = maybeResolveDrift(savedCfg, name)
		if debug {
			fmt.Fprintf(os.Stderr, "[greywall] Loaded saved profile for %q\n", name)
		}
		return savedCfg, nil
	}

	// Fall back to built-in profile (agent or toolchain)
	canonical := profiles.IsKnownAgent(name)
	if canonical != "" {
		profile := profiles.GetAgentProfile(canonical)
		if profile != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall] Using built-in profile for %q\n", name)
			}
			return profile, nil
		}
	}

	return nil, fmt.Errorf("profile %q not found (no saved profile and no built-in profile)\nRun: greywall profiles list", name)
}

// proxyIdentity returns the identity used both as the SOCKS5 login injected
// into the proxy URL and as the greyproxy session container name. greyproxy
// matches a live connection to its session — and thus enforces that session's
// network rules, including --allow — by this login, so the two callers MUST
// derive their value from here to keep them identical.
//
// Precedence (highest wins):
//  1. proxyUserFlag (explicit --proxy-user override)
//  2. cmdName       (auto-detected from the wrapped command)
//  3. "proxy"       (fallback, required by gost for auth)
func proxyIdentity(proxyUserFlag, cmdName string) string {
	switch {
	case proxyUserFlag != "":
		return proxyUserFlag
	case cmdName != "":
		return cmdName
	default:
		return "proxy"
	}
}

// extractCommandName extracts a human-readable command name from the arguments.
// For args like ["opencode"], returns "opencode".
// For -c "opencode --foo", returns "opencode".
// Strips path prefixes (e.g., /usr/bin/opencode -> opencode).
func extractCommandName(args []string, cmdStr string) string {
	var fullPath string
	switch {
	case len(args) > 0:
		fullPath = args[0]
	case cmdStr != "":
		// Take first token from the command string
		parts := strings.Fields(cmdStr)
		if len(parts) > 0 {
			fullPath = parts[0]
		}
	}
	if fullPath == "" {
		return ""
	}
	// Detect macOS app bundles: /path/to/Foo.app/Contents/MacOS/Bar → "Foo.app"
	// This prevents the desktop app from colliding with a CLI tool of the
	// same name (e.g. "Claude.app" vs "claude").
	if idx := strings.Index(fullPath, ".app/Contents/MacOS/"); idx >= 0 {
		return filepath.Base(fullPath[:idx+4]) // include ".app"
	}
	// Strip path prefix
	return filepath.Base(fullPath)
}

// newCheckCmd creates the check subcommand for diagnostics.
func newCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check greywall status, dependencies, and greyproxy connectivity",
		Long: `Run diagnostics to check greywall readiness.

Shows version information, platform dependencies, security features,
and greyproxy installation/running status.`,
		Args: cobra.NoArgs,
		RunE: runCheck,
	}
}

func runCheck(_ *cobra.Command, _ []string) error {
	fmt.Printf("greywall - lightweight, container-free sandbox for running untrusted commands\n")
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Built:   %s\n", buildTime)
	fmt.Printf("Commit:  %s\n", gitCommit)

	steps := sandbox.PrintDependencyStatus()

	status := proxy.Detect()
	brewManaged := proxy.IsBrewManaged(status.Path)

	installHint := "greywall setup"
	upgradeHint := "greywall setup"
	if brewManaged {
		upgradeHint = "brew upgrade greyproxy"
	} else if selfPath, err := os.Executable(); err == nil && proxy.IsBrewManaged(selfPath) {
		installHint = "brew install greyproxy"
	}

	if status.Installed {
		if status.Version != "" {
			fmt.Println(sandbox.CheckOK(fmt.Sprintf("greyproxy (v%s)", status.Version)))
		} else {
			fmt.Println(sandbox.CheckOK("greyproxy"))
		}
		if brewManaged {
			fmt.Println(sandbox.CheckOK("greyproxy installed via Homebrew"))
		}
		if status.Running {
			fmt.Println(sandbox.CheckOK("greyproxy running (SOCKS5 :43052, DNS :43053)"))
			fmt.Printf("    Dashboard: http://localhost:43080\n")
		} else {
			fmt.Println(sandbox.CheckFail("greyproxy running"))
			steps = append(steps, "greywall setup")
		}
		if latest, err := proxy.CheckLatestVersion(); err == nil {
			if proxy.IsOlderVersion(status.Version, latest) {
				fmt.Println(sandbox.CheckFail(fmt.Sprintf("greyproxy up-to-date (v%s available, installed v%s)", latest, status.Version)))
				steps = append(steps, upgradeHint)
			}
		}
	} else {
		fmt.Println(sandbox.CheckFail("greyproxy"))
		fmt.Println(sandbox.CheckFail("greyproxy running"))
		steps = append(steps, installHint)
	}

	if len(steps) > 0 {
		steps = append(steps, "Run 'greywall check' again to verify")
		fmt.Printf("\nNext steps:\n")
		for i, step := range steps {
			fmt.Printf("  %d. %s\n", i+1, step)
		}
	} else {
		fmt.Printf("\nAll checks passed. Welcome to greywall :)\n")
		fmt.Printf("\nGet started:\n")
		fmt.Printf("  1. Open your dashboard: http://localhost:43080\n")
		fmt.Printf("  2. Try it: greywall -- curl https://greyhaven.co\n")
		fmt.Printf("     The request will be blocked — allow it on the dashboard, then try again\n")
		fmt.Printf("  3. Learn a tool: greywall --learning -- opencode\n")
		fmt.Printf("  4. Review the profile: greywall profiles show opencode\n")
		fmt.Printf("  5. Run with the profile: greywall -- opencode\n")
	}

	return nil
}

// newSetupCmd creates the setup subcommand for installing greyproxy.
func newSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Install and start greyproxy (network proxy for sandboxed commands)",
		Long: `Downloads and installs greyproxy from GitHub releases.

greyproxy provides SOCKS5 proxying and DNS resolution for sandboxed commands.
The installer will:
  1. Download the latest greyproxy release for your platform
  2. Install the binary to ~/.local/bin/greyproxy
  3. Register and start a systemd user service`,
		Args: cobra.NoArgs,
		RunE: runSetup,
	}
}

func runSetup(_ *cobra.Command, _ []string) error {
	status := proxy.Detect()

	if status.Installed && status.Running {
		latest, err := proxy.CheckLatestVersion()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not check for updates: %v\n", err)
			fmt.Printf("greyproxy is already installed (v%s) and running.\n", status.Version)
			fmt.Printf("Run 'greywall check' for full status.\n")
			return nil
		}
		if proxy.IsOlderVersion(status.Version, latest) {
			fmt.Printf("greyproxy update available: v%s -> v%s\n", status.Version, latest)
			if proxy.IsBrewManaged(status.Path) {
				fmt.Printf("greyproxy is managed by Homebrew. To update, run:\n")
				fmt.Printf("  brew upgrade greyproxy\n")
				return nil
			}
			fmt.Printf("Upgrading...\n")
			return proxy.Install(proxy.InstallOptions{
				Output: os.Stderr,
			})
		}
		fmt.Printf("greyproxy is already installed (v%s) and running.\n", status.Version)
		fmt.Printf("Run 'greywall check' for full status.\n")
		return nil
	}

	if status.Installed && !status.Running {
		if err := proxy.Start(os.Stderr); err != nil {
			return err
		}
		fmt.Printf("greyproxy started.\n")
		return nil
	}

	// Check if greywall itself was installed via brew; if so, suggest brew for greyproxy too.
	if selfPath, err := os.Executable(); err == nil && proxy.IsBrewManaged(selfPath) {
		fmt.Printf("greyproxy is not installed. Since greywall was installed via Homebrew, run:\n")
		fmt.Printf("  brew install greyproxy\n")
		return nil
	}

	return proxy.Install(proxy.InstallOptions{
		Output: os.Stderr,
	})
}

// newCompletionCmd creates the completion subcommand for shell completions.
func newCompletionCmd(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for greywall.

Examples:
  # Bash (load in current session)
  source <(greywall completion bash)

  # Zsh (load in current session)
  source <(greywall completion zsh)

  # Fish (load in current session)
  greywall completion fish | source

  # PowerShell (load in current session)
  greywall completion powershell | Out-String | Invoke-Expression

To persist completions, redirect output to the appropriate completions
directory for your shell (e.g., /etc/bash_completion.d/ for bash,
${fpath[1]}/_greywall for zsh, ~/.config/fish/completions/greywall.fish for fish).
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
	return cmd
}

// newProfilesCmd creates the profiles subcommand for managing sandbox profiles.
func newProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "profiles",
		Aliases: []string{"templates"},
		Short:   "Manage sandbox profiles",
		Long: `List and inspect sandbox profiles.

Profiles are created by running greywall with --learning and are stored in:
  ` + sandbox.LearnedTemplateDir() + `

Examples:
  greywall profiles list            # List all profiles
  greywall profiles show opencode   # Show the content of a profile
  greywall profiles edit opencode   # Edit a saved profile in $EDITOR`,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			saved, err := sandbox.ListLearnedTemplates()
			if err != nil {
				return fmt.Errorf("failed to list profiles: %w", err)
			}
			if len(saved) > 0 {
				fmt.Printf("Saved profiles (%s):\n\n", sandbox.LearnedTemplateDir())
				for _, t := range saved {
					fmt.Printf("  %s\n", t.Name)
				}
				fmt.Println()
			}

			available := profiles.ListAvailableProfiles()
			if len(available) > 0 {
				fmt.Println("Built-in profiles (not yet saved):")
				fmt.Println()
				for _, a := range available {
					fmt.Printf("  %s\n", a)
				}
				fmt.Println()
			}

			if len(saved) == 0 && len(available) == 0 {
				fmt.Println("No profiles found.")
				fmt.Printf("Create one with: greywall --learning -- <command>\n")
				return nil
			}

			fmt.Println("Show a profile:    greywall profiles show <name>")
			fmt.Println("Edit a profile:    greywall profiles edit <name>")
			fmt.Println("Use a profile:     greywall --profile <name> -- <command>")
			fmt.Println("Combine profiles:  greywall --profile claude,python -- claude")
			return nil
		},
	}

	showCmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show the content of a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			profilePath := sandbox.LearnedTemplatePath(name)
			data, err := os.ReadFile(profilePath) //nolint:gosec // user-specified profile path - intentional
			if err != nil {
				if os.IsNotExist(err) {
					// Fall back to built-in profile registry
					canonical := profiles.IsKnownAgent(name)
					if canonical != "" {
						profile := profiles.GetAgentProfile(canonical)
						if profile != nil {
							out, jsonErr := json.MarshalIndent(profile, "", "  ")
							if jsonErr != nil {
								return fmt.Errorf("failed to serialize profile: %w", jsonErr)
							}
							fmt.Printf("Profile: %s (built-in)\n\n", canonical)
							fmt.Println(string(out))
							return nil
						}
					}
					return fmt.Errorf("profile %q not found\nRun: greywall profiles list", name)
				}
				return fmt.Errorf("failed to read profile: %w", err)
			}
			fmt.Printf("Profile: %s\n", name)
			fmt.Printf("Path:    %s\n\n", profilePath)
			fmt.Print(string(data))
			return nil
		},
	}

	editCmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit a saved profile in your editor",
		Long: `Open a saved profile in $EDITOR for editing. After the editor closes,
the profile is validated. If validation fails, you can re-edit or discard changes.

Only saved profiles (created via --learning) can be edited. To edit built-in
profiles, first save a copy with --learning or copy the output of "profiles show".`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			profilePath := sandbox.LearnedTemplatePath(name)
			if _, err := os.Stat(profilePath); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("profile %q not found (only saved profiles can be edited)\nRun: greywall profiles list", name)
				}
				return fmt.Errorf("failed to access profile %q: %w", name, err)
			}

			editor := os.Getenv("EDITOR")
			if editor == "" {
				editor = os.Getenv("VISUAL")
			}
			if editor == "" {
				editor = "vi"
			}

			// Split editor to support values like "code --wait" or "emacs -nw"
			editorParts := strings.Fields(editor)
			if len(editorParts) == 0 {
				editorParts = []string{"vi"}
			}

			// Save original content for change detection and rollback
			originalData, err := os.ReadFile(profilePath) //nolint:gosec // user-specified profile path
			if err != nil {
				return fmt.Errorf("failed to read profile: %w", err)
			}

			for {
				editorArgs := make([]string, len(editorParts)-1, len(editorParts))
				copy(editorArgs, editorParts[1:])
				editorArgs = append(editorArgs, profilePath)
				editorCmd := exec.Command(editorParts[0], editorArgs...) //nolint:gosec // editor from user env
				editorCmd.Stdin = os.Stdin
				editorCmd.Stdout = os.Stdout
				editorCmd.Stderr = os.Stderr
				if err := editorCmd.Run(); err != nil {
					return fmt.Errorf("editor exited with error: %w", err)
				}

				// Check if file was changed
				newData, err := os.ReadFile(profilePath) //nolint:gosec // same path
				if err != nil {
					return fmt.Errorf("failed to read profile after edit: %w", err)
				}
				if string(newData) == string(originalData) {
					fmt.Println("No changes made.")
					return nil
				}

				// Validate the edited profile
				cfg, err := config.Load(profilePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Validation error: %v\n\n", err)
				} else if cfg == nil {
					// config.Load returns (nil, nil) for empty files
					fmt.Fprintln(os.Stderr, "Validation error: profile is empty")
					err = fmt.Errorf("empty profile")
				}

				if err != nil {
					fmt.Fprint(os.Stderr, "(r)e-edit, (d)iscard changes? [r/d]: ")
					var choice string
					if _, scanErr := fmt.Scanln(&choice); scanErr != nil {
						// Non-interactive or stdin closed — discard to be safe
						choice = "d"
					}
					switch strings.ToLower(strings.TrimSpace(choice)) {
					case "d", "discard":
						if writeErr := os.WriteFile(profilePath, originalData, 0o600); writeErr != nil { //nolint:gosec // user-specified profile path - intentional
							return fmt.Errorf("failed to restore original profile: %w", writeErr)
						}
						fmt.Println("Changes discarded.")
						return nil
					default:
						// Re-edit
						continue
					}
				}

				fmt.Printf("Profile %q updated.\n", name)
				return nil
			}
		},
	}

	cmd.AddCommand(listCmd, showCmd, editCmd)
	return cmd
}

// runLandlockWrapper runs in "wrapper mode" inside the sandbox.
// It applies Landlock restrictions and then execs the user command.
// Usage: greywall --landlock-apply [--debug] -- <command...>
// Config is passed via GREYWALL_CONFIG_JSON environment variable.
func runLandlockWrapper() {
	// Parse arguments: --landlock-apply [--debug] -- <command...>
	args := os.Args[2:] // Skip "greywall" and "--landlock-apply"

	var debugMode bool
	var cmdStart int

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--debug":
			debugMode = true
		case "--":
			cmdStart = i + 1
			goto parseCommand
		default:
			// Assume rest is the command
			cmdStart = i
			goto parseCommand
		}
	}

parseCommand:
	if cmdStart >= len(args) {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Error: no command specified\n")
		os.Exit(1)
	}

	command := args[cmdStart:]

	if debugMode {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Applying Landlock restrictions\n")
	}

	// Only apply Landlock on Linux
	if platform.Detect() == platform.Linux {
		// Load config from environment variable (passed by parent greywall process)
		var cfg *config.Config
		if configJSON := os.Getenv("GREYWALL_CONFIG_JSON"); configJSON != "" {
			cfg = &config.Config{}
			if err := json.Unmarshal([]byte(configJSON), cfg); err != nil {
				if debugMode {
					fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Warning: failed to parse config: %v\n", err)
				}
				cfg = nil
			}
		}
		if cfg == nil {
			cfg = config.Default()
		}

		// Get current working directory for relative path resolution
		cwd, _ := os.Getwd()

		// Apply Landlock restrictions
		err := sandbox.ApplyLandlockFromConfig(cfg, cwd, nil, debugMode)
		if err != nil {
			if debugMode {
				fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Warning: Landlock not applied: %v\n", err)
			}
			// Continue without Landlock - bwrap still provides isolation
		} else if debugMode {
			fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Landlock restrictions applied\n")
		}
	}

	// Find the executable
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Error: command not found: %s\n", command[0]) //nolint:gosec // stderr output
		os.Exit(127)
	}

	if debugMode {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Exec: %s %v\n", execPath, command[1:]) //nolint:gosec // stderr output
	}

	// Sanitize environment (strips LD_PRELOAD, etc.)
	hardenedEnv := sandbox.FilterDangerousEnv(os.Environ())

	// Exec the command (replaces this process)
	err = syscall.Exec(execPath, command, hardenedEnv) //nolint:gosec
	if err != nil {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Exec failed: %v\n", err)
		os.Exit(1)
	}
}

// mergeUnique combines two string slices, removing duplicates while preserving order.
func mergeUnique(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
