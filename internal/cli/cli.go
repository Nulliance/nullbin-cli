// Package cli implements the nullbin-cli command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Nulliance/nullbin-cli/client"
	"github.com/Nulliance/nullbin-cli/internal/config"
	"github.com/Nulliance/nullbin-cli/internal/tty"
)

// BuildInfo carries version metadata injected at build time.
type BuildInfo struct {
	Version string `json:"version"`
}

// App wires I/O streams and environment hooks so the CLI is fully testable.
type App struct {
	Build      BuildInfo
	Stdin      *os.File
	StdinR     io.Reader // optional override for tests
	Stdout     io.Writer
	StdoutFile *os.File // used to detect stdout TTY
	Stderr     io.Writer
	Getenv     func(string) string
	ConfigPath string // optional override for tests
	HTTPClient *http.Client
}

// NewApp creates an App wired to standard OS streams.
func NewApp(version string) *App {
	if version == "" {
		version = "dev"
	}
	return &App{
		Build:      BuildInfo{Version: version},
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		StdoutFile: os.Stdout,
		Stderr:     os.Stderr,
		Getenv:     os.Getenv,
	}
}

func (a *App) stdinReader() io.Reader {
	if a.StdinR != nil {
		return a.StdinR
	}
	return a.Stdin
}

func (a *App) stdinIsTTY() bool {
	if a.StdinR != nil {
		return false
	}
	return tty.IsTTY(a.Stdin)
}

func (a *App) stdoutIsTTY() bool {
	return tty.IsTTY(a.StdoutFile)
}

func (a *App) loadConfig() (config.Config, error) {
	path := a.ConfigPath
	if path == "" {
		var err error
		path, err = config.DefaultPath()
		if err != nil {
			return config.Config{}, err
		}
	}
	return config.Load(path)
}

func (a *App) resolveServer(flagServer, flagAPI string) (string, string, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return "", "", err
	}
	return config.ResolveServer(flagServer, flagAPI, a.Getenv("NULLBIN_SERVER"), a.Getenv("NULLBIN_API"), cfg)
}

func (a *App) newClient(serverOrigin, apiOrigin string) (*client.Client, error) {
	var opts []client.Option
	if apiOrigin != "" {
		opts = append(opts, client.WithAPIOrigin(apiOrigin))
	}
	if a.HTTPClient != nil {
		opts = append(opts, client.WithHTTPClient(a.HTTPClient))
	}
	return client.New(serverOrigin, opts...)
}

// Run executes nullbin-cli with args (excluding argv[0]) and returns an exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printRootUsage()
		return 2
	}

	sub := args[0]
	rest := args[1:]

	var err error
	switch sub {
	case "-h", "--help", "help":
		a.printRootUsage()
		return 0
	case "create":
		err = a.runCreate(ctx, rest)
	case "read":
		err = a.runRead(ctx, rest)
	case "delete":
		err = a.runDelete(ctx, rest)
	case "recipients":
		err = a.runRecipients(ctx, rest)
	case "version":
		err = a.runVersion(ctx, rest)
	default:
		fmt.Fprintf(a.Stderr, "unknown command %q\n\n", sub)
		a.printRootUsage()
		return 2
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func (a *App) printRootUsage() {
	fmt.Fprintf(a.Stderr, `nullbin-cli — zero-knowledge encrypted pastebin CLI

Usage:
  nullbin-cli <command> [flags]

Commands:
  create       Encrypt locally and upload a new paste
  read         Fetch, verify, and decrypt a paste
  delete       Permanently delete a paste using its delete URL
  recipients   List or revoke separate recipient links
  version      Show CLI version (and server version with --server)

Security notes:
  - No default public server is hardcoded. Pass --server, set NULLBIN_SERVER,
    or configure ~/.config/nullbin/config.json (mode 0600).
  - Passwords are never accepted as CLI flag values; use --password (TTY),
    --password-stdin, --password-fd, or --generate-password.
  - Use --url-stdin on read/delete/recipients to keep #keys out of argv.

Run "nullbin-cli <command> --help" for command flags.
`)
}

func (a *App) writeJSON(v any) error {
	enc := json.NewEncoder(a.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type stringListFlag []string

func (s *stringListFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringListFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
