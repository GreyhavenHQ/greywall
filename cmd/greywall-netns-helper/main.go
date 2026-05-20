//go:build linux

// greywall-netns-helper creates and enters a persistent network namespace
// with a tun2socks bridge to an external SOCKS5 proxy. It is intended to be
// installed with file capabilities so it (and only it) can create and enter
// netns as an unprivileged user:
//
//	setcap cap_net_admin,cap_sys_admin+ep /usr/local/bin/greywall-netns-helper
//
// This binary has three user-facing subcommands:
//
//	create  --proxy URL [--tun2socks PATH] [--bridge-port N]
//	    Creates a new netns, sets up tun0 + default route via tun2socks,
//	    pins the netns at /run/greywall/ns-<uuid>, and (if --bridge-port is
//	    given) sets up a bidirectional TCP bridge so a host-netns client
//	    can reach a TCP listener inside the pinned netns. Prints the pin
//	    path and exits. Records all background PIDs in <pin>.pid (one per
//	    line) for later cleanup by `destroy`.
//
//	exec    --netns PATH -- COMMAND [ARGS...]
//	    Enters the pinned netns, drops ALL capabilities, then exec's
//	    COMMAND. Used by greywall's --netns flag to run the wrapped command
//	    inside the netns without handing the caller any privilege.
//
//	destroy PATH
//	    SIGTERMs every recorded pid, unmounts the netns pin, removes the
//	    pin, pid file, and bridge socket.
//
// Plus one internal subcommand used only by `create` to spawn its host-netns
// bridge sibling (you should never invoke it directly):
//
//	_bridge-host --socket PATH --port N
//
// The `exec` subcommand strictly refuses netns paths outside /run/greywall
// and drops all caps (incl. ambient + bounding set) before exec'ing the
// user command.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	pinDir = "/run/greywall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "create":
		cmdCreate(os.Args[2:])
	case "exec":
		cmdExec(os.Args[2:])
	case "destroy":
		cmdDestroy(os.Args[2:])
	case "_bridge-host":
		cmdBridgeHost(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "greywall-netns-helper: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  greywall-netns-helper create --proxy socks5://host:port [--tun2socks PATH] [--bridge-port N]")
	fmt.Fprintln(os.Stderr, "  greywall-netns-helper exec --netns /run/greywall/ns-<id> -- <command> [args...]")
	fmt.Fprintln(os.Stderr, "  greywall-netns-helper destroy /run/greywall/ns-<id>")
}

// -----------------------------------------------------------------------------
// create
// -----------------------------------------------------------------------------

func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	proxy := fs.String("proxy", "", "SOCKS5 proxy URL, e.g. socks5://host:port (required)")
	tun2socksBin := fs.String("tun2socks", "/usr/local/bin/tun2socks", "Path to tun2socks binary")
	bridgePort := fs.Int("bridge-port", 0, "If set, bridge host-netns TCP port N <-> inside-netns TCP 127.0.0.1:N via a Unix socket")
	debug := fs.Bool("debug", false, "Verbose stderr logging")
	_ = fs.Parse(args)

	if *proxy == "" {
		die("create: --proxy is required")
	}
	if _, err := os.Stat(*tun2socksBin); err != nil {
		die("create: tun2socks binary not found at %s: %v", *tun2socksBin, err)
	}
	if _, err := exec.LookPath("socat"); err != nil && *bridgePort != 0 {
		die("create: --bridge-port requires socat in PATH")
	}
	selfExe, err := os.Executable()
	if err != nil {
		die("create: cannot resolve own executable path: %v", err)
	}

	// Generate the pin path up-front so we can pass its .sock sibling to
	// the host-netns bridge launcher before we unshare.
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		die("create: mkdir %s: %v", pinDir, err)
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		die("create: rand: %v", err)
	}
	pinPath := filepath.Join(pinDir, fmt.Sprintf("ns-%s", hex.EncodeToString(id)))
	socketPath := pinPath + ".sock"

	var pids []int // collect for the sidecar pidfile

	// --- 1. Host-netns bridge sibling --------------------------------------
	//
	// Spawn this BEFORE unshare(CLONE_NEWNET) so it stays in the host netns.
	// It polls until the Unix socket appears, then execs socat to accept TCP
	// on 127.0.0.1:<bridge-port> and forward to the Unix socket. We never
	// put the user-supplied port directly on the command line to socat
	// without --bind=127.0.0.1, so nothing else on the host can connect.
	if *bridgePort != 0 {
		args := []string{
			selfExe, "_bridge-host",
			"--socket", socketPath,
			"--port", strconv.Itoa(*bridgePort),
		}
		if *debug {
			args = append(args, "--debug")
		}
		//nolint:gosec // selfExe + subcommand are trusted
		bridge := exec.Command(args[0], args[1:]...)
		devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			die("create: open /dev/null: %v", err)
		}
		bridge.Stdin = devnull
		bridge.Stdout = devnull
		bridge.Stderr = devnull
		bridge.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := bridge.Start(); err != nil {
			_ = devnull.Close()
			die("create: spawn host-netns bridge: %v", err)
		}
		_ = devnull.Close()
		pids = append(pids, bridge.Process.Pid)
		if *debug {
			fmt.Fprintf(os.Stderr, "[netns-helper] host-bridge pid=%d (TCP 127.0.0.1:%d <- unix://%s)\n",
				bridge.Process.Pid, *bridgePort, socketPath)
		}
	}

	// --- 2. Enter a fresh netns --------------------------------------------
	//
	// Lock OS thread so the netns unshare only affects this thread. We
	// exec tun2socks (as a child) and exit, so the lock is temporary.
	runtime.LockOSThread()

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = killPids(pids) // kill the orphaned host-netns bridge sibling
		die("create: unshare(CLONE_NEWNET) failed: %v (need CAP_SYS_ADMIN)", err)
	}

	// File caps put CAP_NET_ADMIN/CAP_SYS_ADMIN in our permitted+effective,
	// but children do NOT inherit those unless we raise them into the
	// ambient set. `ip` and `tun2socks` are separate binaries that need
	// CAP_NET_ADMIN to manipulate interfaces.
	if err := raiseAmbient(capNetAdmin); err != nil {
		_ = killPids(pids)
		die("create: raise ambient CAP_NET_ADMIN: %v", err)
	}

	// We're now in a fresh netns. lo is down; tun0 does not yet exist.
	setupCmds := [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "tuntap", "add", "dev", "tun0", "mode", "tun"},
		{"ip", "addr", "add", "198.18.0.1/15", "dev", "tun0"},
		{"ip", "link", "set", "tun0", "up"},
		{"ip", "route", "add", "default", "via", "198.18.0.1", "dev", "tun0"},
	}
	for _, c := range setupCmds {
		cmd := exec.Command(c[0], c[1:]...) //nolint:gosec // args are fixed strings
		if out, err := cmd.CombinedOutput(); err != nil {
			_ = killPids(pids)
			die("create: %s failed: %v\n  %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
		if *debug {
			fmt.Fprintf(os.Stderr, "[netns-helper] %s ok\n", strings.Join(c, " "))
		}
	}

	// --- 3. Pin the netns at /run/greywall/ns-<uuid> -----------------------

	// Pre-create the mount target as an empty regular file.
	f, err := os.OpenFile(pinPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		_ = killPids(pids)
		die("create: pin file %s: %v", pinPath, err)
	}
	_ = f.Close()

	if err := unix.Mount("/proc/self/ns/net", pinPath, "", unix.MS_BIND, ""); err != nil {
		_ = killPids(pids)
		_ = os.Remove(pinPath)
		die("create: bind mount netns to %s: %v", pinPath, err)
	}

	// --- 4. tun2socks inside the netns -------------------------------------

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		cleanupAll(pinPath, pids)
		die("create: open /dev/null: %v", err)
	}
	defer func() { _ = devnull.Close() }()

	tun2socksCmd := exec.Command(*tun2socksBin, "-device", "tun0", "-proxy", *proxy) //nolint:gosec // proxy/tun2socks validated above
	tun2socksCmd.Stdin = devnull
	tun2socksCmd.Stdout = devnull
	tun2socksCmd.Stderr = devnull
	tun2socksCmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := tun2socksCmd.Start(); err != nil {
		cleanupAll(pinPath, pids)
		die("create: tun2socks start: %v", err)
	}
	pids = append(pids, tun2socksCmd.Process.Pid)
	if *debug {
		fmt.Fprintf(os.Stderr, "[netns-helper] tun2socks pid=%d\n", tun2socksCmd.Process.Pid)
	}

	// --- 5. Inside-netns bridge socat (only when --bridge-port given) ------
	//
	// socat UNIX-LISTEN:<socket>,fork,reuseaddr TCP:127.0.0.1:<port>
	// listens on the shared-filesystem Unix socket and forwards each
	// accepted connection to the TCP port where opencode will bind.
	// Because we're inside the netns, the TCP endpoint is opencode's
	// in-netns loopback.
	if *bridgePort != 0 {
		socatArgs := []string{
			"socat",
			fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr,mode=0660", socketPath),
			fmt.Sprintf("TCP:127.0.0.1:%d", *bridgePort),
		}
		sc := exec.Command(socatArgs[0], socatArgs[1:]...) //nolint:gosec // args trusted
		sc.Stdin = devnull
		sc.Stdout = devnull
		sc.Stderr = devnull
		sc.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := sc.Start(); err != nil {
			cleanupAll(pinPath, pids)
			die("create: inside-netns socat start: %v", err)
		}
		pids = append(pids, sc.Process.Pid)
		if *debug {
			fmt.Fprintf(os.Stderr, "[netns-helper] inside-socat pid=%d (unix://%s -> tcp://127.0.0.1:%d)\n",
				sc.Process.Pid, socketPath, *bridgePort)
		}
	}

	// --- 6. Record pids for `destroy` --------------------------------------

	var sb strings.Builder
	for _, p := range pids {
		fmt.Fprintf(&sb, "%d\n", p)
	}
	if err := os.WriteFile(pinPath+".pid", []byte(sb.String()), 0o644); err != nil {
		if *debug {
			fmt.Fprintf(os.Stderr, "[netns-helper] warning: failed to write pidfile: %v\n", err)
		}
	}

	fmt.Println(pinPath)
}

func cleanupPin(path string) {
	_ = unix.Unmount(path, 0)
	_ = os.Remove(path)
	_ = os.Remove(path + ".pid")
	_ = os.Remove(path + ".sock")
}

func cleanupAll(path string, pids []int) {
	_ = killPids(pids)
	cleanupPin(path)
}

func killPids(pids []int) error {
	for _, p := range pids {
		if p > 0 {
			_ = syscall.Kill(p, syscall.SIGTERM)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// _bridge-host (internal)
// -----------------------------------------------------------------------------

func cmdBridgeHost(args []string) {
	fs := flag.NewFlagSet("_bridge-host", flag.ExitOnError)
	socketPath := fs.String("socket", "", "Unix socket path to connect to (required)")
	port := fs.Int("port", 0, "TCP port to listen on at 127.0.0.1 (required)")
	debug := fs.Bool("debug", false, "Verbose stderr logging")
	_ = fs.Parse(args)

	if *socketPath == "" || *port == 0 {
		die("_bridge-host: --socket and --port are required")
	}
	if err := validatePinPath(strings.TrimSuffix(*socketPath, ".sock")); err != nil {
		// We only accept sockets that live alongside a valid pin path, so
		// this binary's file caps can't be leveraged to proxy arbitrary
		// Unix sockets.
		die("_bridge-host: %v", err)
	}

	// Wait up to 10s for the Unix socket to appear — the inside-netns
	// socat only starts it after the parent finishes unshare + tun setup.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(*socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			die("_bridge-host: timeout waiting for %s", *socketPath)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Drop all caps before handing control to socat; we don't need them
	// (port > 1024 doesn't require CAP_NET_BIND_SERVICE) and the less
	// privilege the better.
	_ = dropAllCaps()
	_ = clearBoundingSet()

	socatPath, err := exec.LookPath("socat")
	if err != nil {
		die("_bridge-host: socat not in PATH: %v", err)
	}
	socatArgs := []string{
		"socat",
		fmt.Sprintf("TCP4-LISTEN:%d,bind=127.0.0.1,fork,reuseaddr", *port),
		fmt.Sprintf("UNIX-CONNECT:%s", *socketPath),
	}
	if *debug {
		fmt.Fprintf(os.Stderr, "[netns-helper:_bridge-host] exec %s\n", strings.Join(socatArgs, " "))
	}
	if err := syscall.Exec(socatPath, socatArgs, os.Environ()); err != nil { //nolint:gosec
		die("_bridge-host: exec socat: %v", err)
	}
}

// -----------------------------------------------------------------------------
// exec
// -----------------------------------------------------------------------------

func cmdExec(args []string) {
	// Parse: --netns PATH [--] <command> [args...]
	var netnsPath string
	var cmdStart int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--netns":
			if i+1 >= len(args) {
				die("exec: --netns requires a value")
			}
			netnsPath = args[i+1]
			i++
		case "--":
			cmdStart = i + 1
			goto runit
		default:
			cmdStart = i
			goto runit
		}
	}
runit:
	if netnsPath == "" {
		die("exec: --netns is required")
	}
	if cmdStart >= len(args) {
		die("exec: no command specified")
	}
	if err := validatePinPath(netnsPath); err != nil {
		die("exec: %v", err)
	}
	command := args[cmdStart:]

	// Open the netns fd first (while we still have CAP_SYS_ADMIN).
	fd, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		die("exec: open %s: %v", netnsPath, err)
	}

	// Lock the thread, enter the netns, then drop caps. We will exec
	// momentarily which replaces the whole process so the lock is safe.
	runtime.LockOSThread()

	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		die("exec: setns: %v", err)
	}
	_ = unix.Close(fd)

	if err := dropAllCaps(); err != nil {
		die("exec: dropAllCaps: %v", err)
	}
	// Also clear the bounding set so exec'd program cannot gain caps from
	// any file caps on the target binary.
	if err := clearBoundingSet(); err != nil {
		// Non-fatal: bounding-set clear can fail in some containers, but
		// we've already cleared permitted+effective which is the primary
		// defense.
		fmt.Fprintf(os.Stderr, "[netns-helper] warning: clearBoundingSet: %v\n", err)
	}

	// Find the target and exec (replaces current process).
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		die("exec: command not found: %s", command[0])
	}
	if err := syscall.Exec(execPath, command, os.Environ()); err != nil { //nolint:gosec
		die("exec: syscall.Exec: %v", err)
	}
}

// validatePinPath rejects anything outside pinDir to prevent abuse of the
// file caps for arbitrary netns entry.
func validatePinPath(path string) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", path, err)
	}
	if !strings.HasPrefix(clean, pinDir+"/") {
		return fmt.Errorf("path must be under %s (got %s)", pinDir, clean)
	}
	if strings.Contains(clean, "/..") {
		return errors.New("path must not contain ..")
	}
	return nil
}

// -----------------------------------------------------------------------------
// destroy
// -----------------------------------------------------------------------------

func cmdDestroy(args []string) {
	if len(args) != 1 {
		die("destroy: exactly one pin path required")
	}
	path := args[0]
	if err := validatePinPath(path); err != nil {
		die("destroy: %v", err)
	}

	// Read all recorded pids; kill each with SIGTERM.
	if data, err := os.ReadFile(path + ".pid"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if pid, perr := strconv.Atoi(line); perr == nil && pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
	}

	cleanupPin(path)
}

// -----------------------------------------------------------------------------
// capability helpers
// -----------------------------------------------------------------------------

// capUserHeader matches Linux's cap_user_header_t.
type capUserHeader struct {
	version uint32
	pid     int32
}

// capUserData matches Linux's cap_user_data_t for _LINUX_CAPABILITY_VERSION_3.
type capUserData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// _LINUX_CAPABILITY_VERSION_3 (linux/capability.h)
const linuxCapabilityVersion3 = 0x20080522

// Capability numbers we use; matches include/uapi/linux/capability.h.
const (
	capNetAdmin = 12
	capSysAdmin = 21
)

// prctlCapAmbientClearAll = PR_CAP_AMBIENT_CLEAR_ALL (prctl.h).
const prctlCapAmbientClearAll = 4

// raiseAmbient promotes a capability into the ambient set so that children
// exec'd by this process inherit it. The cap must already be in both the
// permitted and inheritable sets — we add it to inheritable first.
func raiseAmbient(capNum int) error {
	hdr := capUserHeader{version: linuxCapabilityVersion3, pid: 0}
	var data [2]capUserData
	if _, _, errno := unix.Syscall(
		unix.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)),  //nolint:gosec
		uintptr(unsafe.Pointer(&data)), //nolint:gosec
		0,
	); errno != 0 {
		return fmt.Errorf("capget: %w", errno)
	}

	idx := capNum / 32
	bit := uint32(1) << (capNum % 32) //nolint:gosec // capNum fits in uint32
	if data[idx].permitted&bit == 0 {
		return fmt.Errorf("cap %d not in permitted set (file caps missing?)", capNum)
	}
	data[idx].inheritable |= bit

	if _, _, errno := unix.Syscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),  //nolint:gosec
		uintptr(unsafe.Pointer(&data)), //nolint:gosec
		0,
	); errno != 0 {
		return fmt.Errorf("capset (add to inheritable): %w", errno)
	}

	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(capNum), 0, 0); err != nil {
		return fmt.Errorf("PR_CAP_AMBIENT_RAISE(%d): %w", capNum, err)
	}
	return nil
}

// dropAllCaps clears effective, permitted, inheritable AND the ambient
// capability set for the calling thread. We call this just before
// syscall.Exec so the exec'd program starts with empty caps and cannot
// pick any up via ambient inheritance.
func dropAllCaps() error {
	// Clear ambient first (requires only caller privilege; no caps needed).
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, prctlCapAmbientClearAll, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_CAP_AMBIENT_CLEAR_ALL: %w", err)
	}

	hdr := capUserHeader{version: linuxCapabilityVersion3, pid: 0}
	var data [2]capUserData // all zero
	_, _, errno := unix.Syscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),  //nolint:gosec // syscall needs pointer
		uintptr(unsafe.Pointer(&data)), //nolint:gosec // syscall needs pointer
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// clearBoundingSet drops every capability from the thread's bounding set
// via repeated PR_CAPBSET_DROP calls. Enumerates 0..64 which covers all
// currently-defined caps.
func clearBoundingSet() error {
	for capNum := 0; capNum < 64; capNum++ {
		// Ignore EINVAL for unknown cap numbers.
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capNum), 0, 0, 0)
	}
	return nil
}

// -----------------------------------------------------------------------------

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "greywall-netns-helper: "+format+"\n", args...)
	os.Exit(1)
}
