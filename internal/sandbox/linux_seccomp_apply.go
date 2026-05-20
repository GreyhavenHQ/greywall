//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sockFilter mirrors struct sock_filter from linux/filter.h.
// Layout must match exactly: 2-byte code, 1-byte jt, 1-byte jf, 4-byte k.
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog mirrors struct sock_fprog from linux/filter.h.
type sockFprog struct {
	len    uint16
	_      [6]byte // padding so filter is 8-aligned on 64-bit
	filter *sockFilter
}

// SECCOMP_SET_MODE_FILTER is the op for the seccomp() syscall that loads
// a classic BPF filter. See include/uapi/linux/seccomp.h.
const SECCOMP_SET_MODE_FILTER = 1

// ApplySeccompFilter loads the same BPF program greywall normally hands to
// bwrap --seccomp, but loads it directly into the current process via
// prctl(PR_SET_NO_NEW_PRIVS) + seccomp(SECCOMP_SET_MODE_FILTER, ...). This
// allows --no-bwrap mode to enforce syscall restrictions without any
// namespace magic.
//
// PR_SET_NO_NEW_PRIVS may already have been set by Landlock's Apply(); that's
// fine — prctl is idempotent. Calling it here too keeps this function safe to
// use standalone (without Landlock).
func ApplySeccompFilter(debug bool) error {
	program, err := generateBPFInstructions()
	if err != nil {
		return fmt.Errorf("seccomp: failed to generate BPF program: %w", err)
	}

	// Convert our internal representation to struct sock_filter.
	filter := make([]sockFilter, len(program))
	for i, inst := range program {
		filter[i] = sockFilter{
			code: inst.code,
			jt:   inst.jt,
			jf:   inst.jf,
			k:    inst.k,
		}
	}

	// PR_SET_NO_NEW_PRIVS is a prerequisite for loading a seccomp filter as
	// an unprivileged process. Idempotent — Landlock may already have set it.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("seccomp: PR_SET_NO_NEW_PRIVS failed: %w", err)
	}

	prog := sockFprog{
		len:    uint16(len(filter)), //nolint:gosec // len bounded by DangerousSyscalls size
		filter: &filter[0],
	}

	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		SECCOMP_SET_MODE_FILTER,
		0, // flags
		uintptr(unsafe.Pointer(&prog)), //nolint:gosec // required for syscall
	)
	if errno != 0 {
		return fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER) failed: %w", errno)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall:seccomp] Loaded filter directly (%d instructions, %d syscalls blocked)\n",
			len(filter), len(DangerousSyscalls))
	}

	return nil
}
