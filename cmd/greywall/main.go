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
	"strconv"
	"strings"
	"syscall"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/platform"
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
	debug         bool
	monitor       bool
	settingsPath  string
	proxyURL      string
	httpProxyURL  string
	dnsAddr       string
	cmdString     string
	exposePorts   []string
	exitCode      int
	showVersion   bool
	linuxFeatures bool
	learning      bool
	templateName  string
)

func main() {
	// Check for internal --landlock-apply mode (used inside sandbox)
	// This must be checked before cobra to avoid flag conflicts
	if len(os.Args) >= 2 && os.Args[1] == "--landlock-apply" {
		runLandlockWrapper()
		return
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
  greywall --learning -- opencode                                # Learn filesystem needs

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
  }
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
	rootCmd.Flags().StringVarP(&cmdString, "c", "c", "", "Run command string directly (like sh -c)")
	rootCmd.Flags().StringArrayVarP(&exposePorts, "port", "p", nil, "Expose port for inbound connections (can be used multiple times)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information")
	rootCmd.Flags().BoolVar(&linuxFeatures, "linux-features", false, "Show available Linux security features and exit")
	rootCmd.Flags().BoolVar(&learning, "learning", false, "Run in learning mode: trace filesystem access and generate a config template")
	rootCmd.Flags().StringVar(&templateName, "template", "", "Load a specific learned template by name (see: greywall templates list)")

	rootCmd.Flags().SetInterspersed(true)

	rootCmd.AddCommand(newCompletionCmd(rootCmd))
	rootCmd.AddCommand(newTemplatesCmd())
	rootCmd.AddCommand(newCheckCmd())
	rootCmd.AddCommand(newSetupCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func runCommand(cmd *cobra.Command, args []string) error {
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

	// Extract command name for learned template lookup
	cmdName := extractCommandName(args, cmdString)

	// Load learned template (when NOT in learning mode)
	if !learning {
		// Determine which template to load: --template flag takes priority
		var templatePath string
		var templateLabel string
		if templateName != "" {
			templatePath = sandbox.LearnedTemplatePath(templateName)
			templateLabel = templateName
		} else if cmdName != "" {
			templatePath = sandbox.LearnedTemplatePath(cmdName)
			templateLabel = cmdName
		}

		if templatePath != "" {
			learnedCfg, loadErr := config.Load(templatePath)
			switch {
			case loadErr != nil:
				if debug {
					fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to load learned template: %v\n", loadErr)
				}
			case learnedCfg != nil:
				cfg = config.Merge(cfg, learnedCfg)
				if debug {
					fmt.Fprintf(os.Stderr, "[greywall] Auto-loaded learned template for %q\n", templateLabel)
				}
			case templateName != "":
				// Explicit --template but file doesn't exist
				return fmt.Errorf("learned template %q not found at %s\nRun: greywall templates list", templateName, templatePath)
			case cmdName != "":
				// No template found for this command - suggest creating one
				fmt.Fprintf(os.Stderr, "[greywall] No learned template for %q. Run with --learning to create one.\n", cmdName)
			}
		}
	}

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
	// - If a command name is available, use it as the username with "proxy" as password.
	// - If no command name, default to "proxy:proxy" (required by gost for auth).
	// This always overrides any existing credentials in the URL.
	if cfg.Network.ProxyURL != "" {
		if u, err := url.Parse(cfg.Network.ProxyURL); err == nil {
			proxyUser := "proxy"
			if cmdName != "" {
				proxyUser = cmdName
			}
			u.User = url.UserPassword(proxyUser, "proxy")
			cfg.Network.ProxyURL = u.String()
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall] Auto-set proxy credentials to %q:proxy\n", proxyUser)
			}
		}
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

	sandboxedCommand, err := manager.WrapCommand(command)
	if err != nil {
		return fmt.Errorf("failed to wrap command: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Sandboxed command: %s\n", sandboxedCommand)
		fmt.Fprintf(os.Stderr, "[greywall] Executing: sh -c %q\n", sandboxedCommand)
	}

	hardenedEnv := sandbox.GetHardenedEnv()
	if debug {
		if stripped := sandbox.GetStrippedEnvVars(os.Environ()); len(stripped) > 0 {
			fmt.Fprintf(os.Stderr, "[greywall] Stripped dangerous env vars: %v\n", stripped)
		}
	}

	execCmd := exec.Command("sh", "-c", sandboxedCommand) //nolint:gosec // sandboxedCommand is constructed from user input - intentional
	execCmd.Env = hardenedEnv
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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
		sigCount := 0
		for sig := range sigChan {
			sigCount++
			if execCmd.Process == nil {
				continue
			}
			// First signal: graceful termination; second signal: force kill
			if sigCount >= 2 {
				_ = execCmd.Process.Kill()
			} else {
				_ = execCmd.Process.Signal(sig)
			}
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

	// Generate learned template after command completes successfully.
	// Skip template generation if the command failed — the strace trace
	// is likely incomplete and would produce an unreliable template.
	if learning && manager.IsLearning() {
		if commandFailed {
			fmt.Fprintf(os.Stderr, "[greywall] Skipping template generation: command exited with code %d\n", exitCode)
		} else {
			fmt.Fprintf(os.Stderr, "[greywall] Analyzing filesystem access patterns...\n")
			templatePath, genErr := manager.GenerateLearnedTemplate(cmdName)
			if genErr != nil {
				fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to generate template: %v\n", genErr)
			} else {
				fmt.Fprintf(os.Stderr, "[greywall] Template saved to: %s\n", templatePath)
				fmt.Fprintf(os.Stderr, "[greywall] Next run will auto-load this template.\n")
			}
		}
	}

	return nil
}

// extractCommandName extracts a human-readable command name from the arguments.
// For args like ["opencode"], returns "opencode".
// For -c "opencode --foo", returns "opencode".
// Strips path prefixes (e.g., /usr/bin/opencode -> opencode).
func extractCommandName(args []string, cmdStr string) string {
	var name string
	switch {
	case len(args) > 0:
		name = args[0]
	case cmdStr != "":
		// Take first token from the command string
		parts := strings.Fields(cmdStr)
		if len(parts) > 0 {
			name = parts[0]
		}
	}
	if name == "" {
		return ""
	}
	// Strip path prefix
	return filepath.Base(name)
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
	if status.Installed {
		if status.Version != "" {
			fmt.Println(sandbox.CheckOK(fmt.Sprintf("greyproxy (v%s)", status.Version)))
		} else {
			fmt.Println(sandbox.CheckOK("greyproxy"))
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
				steps = append(steps, "greywall setup")
			}
		}
	} else {
		fmt.Println(sandbox.CheckFail("greyproxy"))
		fmt.Println(sandbox.CheckFail("greyproxy running"))
		steps = append(steps, "greywall setup")
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
		fmt.Printf("  4. Review the template: greywall templates show opencode\n")
		fmt.Printf("  5. Run with the template: greywall -- opencode\n")
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
			fmt.Printf("greyproxy update available: v%s → v%s\n", status.Version, latest)
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

// newTemplatesCmd creates the templates subcommand for managing learned templates.
func newTemplatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "templates",
		Short: "Manage learned sandbox templates",
		Long: `List and inspect learned sandbox templates.

Templates are created by running greywall with --learning and are stored in:
  ` + sandbox.LearnedTemplateDir() + `

Examples:
  greywall templates list            # List all learned templates
  greywall templates show opencode   # Show the content of a template`,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all learned templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			templates, err := sandbox.ListLearnedTemplates()
			if err != nil {
				return fmt.Errorf("failed to list templates: %w", err)
			}
			if len(templates) == 0 {
				fmt.Println("No learned templates found.")
				fmt.Printf("Create one with: greywall --learning -- <command>\n")
				return nil
			}
			fmt.Printf("Learned templates (%s):\n\n", sandbox.LearnedTemplateDir())
			for _, t := range templates {
				fmt.Printf("  %s\n", t.Name)
			}
			fmt.Println()
			fmt.Println("Show a template: greywall templates show <name>")
			fmt.Println("Use a template:  greywall --template <name> -- <command>")
			return nil
		},
	}

	showCmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show the content of a learned template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			templatePath := sandbox.LearnedTemplatePath(name)
			data, err := os.ReadFile(templatePath) //nolint:gosec // user-specified template path - intentional
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("template %q not found\nRun: greywall templates list", name)
				}
				return fmt.Errorf("failed to read template: %w", err)
			}
			fmt.Printf("Template: %s\n", name)
			fmt.Printf("Path:     %s\n\n", templatePath)
			fmt.Print(string(data))
			return nil
		},
	}

	cmd.AddCommand(listCmd, showCmd)
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
