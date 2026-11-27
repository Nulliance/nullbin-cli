//go:build unix && !linux

// Package procsec applies OS-level process hardening at CLI startup.
package procsec

import "syscall"

// Harden restricts file creation permissions to owner-only (umask 077) and
// disables core dumps (RLIMIT_CORE=0).
func Harden() {
	syscall.Umask(0o077)
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
