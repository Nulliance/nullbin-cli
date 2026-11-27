//go:build !unix

// Package procsec applies OS-level process hardening at CLI startup.
package procsec

// Harden is a no-op on non-Unix platforms.
func Harden() {}
