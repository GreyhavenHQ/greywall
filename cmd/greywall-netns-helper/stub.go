//go:build !linux

// Stub for non-Linux platforms: greywall-netns-helper is a Linux-only binary
// that relies on CLONE_NEWNET + Landlock/seccomp on Linux. This file exists
// so `go build ./...` on macOS (for developer convenience) still succeeds.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "greywall-netns-helper is only supported on Linux")
	os.Exit(1)
}
