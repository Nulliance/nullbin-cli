//go:build linux

// Package procsec applies OS-level process hardening at CLI startup (disabling
// core dumps, blocking ptrace on Linux, and restricting umask).
package procsec

import "syscall"

const prSetDumpable = 4 // PR_SET_DUMPABLE from <linux/prctl.h>

// Harden restricts file creation permissions to owner-only (umask 077),
// disables core dumps (RLIMIT_CORE=0), and marks the process non-dumpable
// (PR_SET_DUMPABLE=0) to block non-root ptrace and /proc/<pid>/mem reads.
func Harden() {
	syscall.Umask(0o077)
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	_, _, _ = syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
}
