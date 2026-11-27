// Package config loads and validates ~/.config/nullbin/config.json with strict
// permission and symlink checks (fail-closed, never hardcodes a default server).
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Nulliance/nullbin-cli/link"
)

const maxConfigBytes = 16 * 1024

// Config represents ~/.config/nullbin/config.json.
type Config struct {
	Server string `json:"server,omitempty"`
	API    string `json:"api,omitempty"`
}

// DefaultPath returns ~/.config/nullbin/config.json.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".config", "nullbin", "config.json"), nil
}

// Load reads and validates a config file. If the file does not exist, an empty
// Config and nil error are returned. Symlinks, non-regular files, unknown JSON
// fields, invalid origins, and insecure POSIX permissions (> 0600) fail closed.
func Load(path string) (Config, error) {
	var cfg Config
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("stat config %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return cfg, fmt.Errorf("refusing to read config file %s: symbolic links are not allowed", path)
	}
	if !info.Mode().IsRegular() {
		return cfg, fmt.Errorf("refusing to read config file %s: not a regular file", path)
	}
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm&0o077 != 0 {
			return cfg, fmt.Errorf("config file %s has overly permissive mode %04o; run: chmod 600 %s", path, perm, path)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	// Re-check opened fd metadata to avoid TOCTOU swap.
	finfo, err := f.Stat()
	if err != nil {
		return cfg, err
	}
	if !os.SameFile(info, finfo) || !finfo.Mode().IsRegular() {
		return cfg, fmt.Errorf("config file %s changed during open", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(data) > maxConfigBytes {
		return cfg, fmt.Errorf("config file %s exceeds %d bytes", path, maxConfigBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("invalid config JSON in %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, fmt.Errorf("unexpected trailing data in %s", path)
	}

	if cfg.Server != "" {
		origin, err := link.ValidateOrigin(cfg.Server)
		if err != nil {
			return Config{}, fmt.Errorf("invalid server in %s: %w", path, err)
		}
		cfg.Server = origin
	}
	if cfg.API != "" {
		origin, err := link.ValidateOrigin(cfg.API)
		if err != nil {
			return Config{}, fmt.Errorf("invalid api in %s: %w", path, err)
		}
		cfg.API = origin
	}
	return cfg, nil
}

// Save writes cfg atomically with mode 0600 (parent dir 0700).
func Save(path string, cfg Config) error {
	if cfg.Server != "" {
		origin, err := link.ValidateOrigin(cfg.Server)
		if err != nil {
			return err
		}
		cfg.Server = origin
	}
	if cfg.API != "" {
		origin, err := link.ValidateOrigin(cfg.API)
		if err != nil {
			return err
		}
		cfg.API = origin
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmpPath := filepath.Join(dir, ".config-tmp-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

// ResolveServer determines the target server and optional API origin using
// strict fail-closed precedence:
//  1. Explicit flags (--server, --api)
//  2. Environment variables (NULLBIN_SERVER, NULLBIN_API)
//  3. User config file (~/.config/nullbin/config.json)
//
// An API origin from a lower-precedence source is never mixed with a server
// overridden at a higher precedence.
func ResolveServer(flagServer, flagAPI, envServer, envAPI string, cfg Config) (serverOrigin, apiOrigin string, err error) {
	flagServer = strings.TrimSpace(flagServer)
	flagAPI = strings.TrimSpace(flagAPI)
	envServer = strings.TrimSpace(envServer)
	envAPI = strings.TrimSpace(envAPI)

	switch {
	case flagServer != "":
		serverOrigin = flagServer
		apiOrigin = flagAPI
	case envServer != "":
		serverOrigin = envServer
		if flagAPI != "" {
			apiOrigin = flagAPI
		} else {
			apiOrigin = envAPI
		}
	case cfg.Server != "":
		serverOrigin = cfg.Server
		if flagAPI != "" {
			apiOrigin = flagAPI
		} else if envAPI != "" {
			apiOrigin = envAPI
		} else {
			apiOrigin = cfg.API
		}
	default:
		return "", "", errors.New("no Nullbin server configured: pass --server <origin>, set NULLBIN_SERVER, or configure ~/.config/nullbin/config.json")
	}

	serverOrigin, err = link.ValidateOrigin(serverOrigin)
	if err != nil {
		return "", "", fmt.Errorf("invalid server origin: %w", err)
	}
	if apiOrigin != "" {
		apiOrigin, err = link.ValidateOrigin(apiOrigin)
		if err != nil {
			return "", "", fmt.Errorf("invalid API origin: %w", err)
		}
	}
	return serverOrigin, apiOrigin, nil
}
