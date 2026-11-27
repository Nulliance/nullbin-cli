package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"

	"github.com/Nulliance/nullbin-cli/client"
	"github.com/Nulliance/nullbin-cli/format"
	"github.com/Nulliance/nullbin-cli/internal/tty"
	"github.com/Nulliance/nullbin-cli/link"
)

func (a *App) runDelete(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		urlStdin   bool
		serverFlag string
		apiFlag    string
		jsonOut    bool
	)
	fs.BoolVar(&urlStdin, "url-stdin", false, "Read delete URL from stdin (avoids exposing delete token in argv)")
	fs.StringVar(&serverFlag, "server", "", "Override server origin from the delete URL")
	fs.StringVar(&apiFlag, "api", "", "Explicit API origin for split deployments")
	fs.BoolVar(&jsonOut, "json", false, "Output machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	rawURL, err := a.readSingleURL(urlStdin, fs.Args(), "usage: nullbin-cli delete [flags] <delete-url> (or --url-stdin)")
	if err != nil {
		return err
	}
	dl, err := link.ParseDeleteURL(rawURL)
	if err != nil {
		return err
	}

	serverOrigin, apiOrigin, err := overrideOrigins(dl.Origin, serverFlag, apiFlag)
	if err != nil {
		return err
	}
	c, err := a.newClient(serverOrigin, apiOrigin)
	if err != nil {
		return err
	}
	if err := c.Delete(ctx, dl); err != nil {
		return err
	}

	if jsonOut {
		return a.writeJSON(map[string]any{
			"id":      dl.ID,
			"deleted": true,
		})
	}
	fmt.Fprintf(a.Stdout, "Deleted paste %s\n", dl.ID)
	return nil
}

func (a *App) runRecipients(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nullbin-cli recipients <list|revoke> [flags]")
	}
	switch args[0] {
	case "list":
		return a.runRecipientsList(ctx, args[1:])
	case "revoke":
		return a.runRecipientsRevoke(ctx, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(a.Stderr, "Usage:\n  nullbin-cli recipients list [flags] <delete-url>\n  nullbin-cli recipients revoke [flags] <delete-url> <index>")
		return flag.ErrHelp
	default:
		return fmt.Errorf("unknown recipients subcommand %q (expected list or revoke)", args[0])
	}
}

func (a *App) runRecipientsList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("recipients list", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		urlStdin   bool
		serverFlag string
		apiFlag    string
		jsonOut    bool
	)
	fs.BoolVar(&urlStdin, "url-stdin", false, "Read delete URL from stdin")
	fs.StringVar(&serverFlag, "server", "", "Override server origin from the delete URL")
	fs.StringVar(&apiFlag, "api", "", "Explicit API origin for split deployments")
	fs.BoolVar(&jsonOut, "json", false, "Output machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	rawURL, err := a.readSingleURL(urlStdin, fs.Args(), "usage: nullbin-cli recipients list [flags] <delete-url> (or --url-stdin)")
	if err != nil {
		return err
	}
	dl, err := link.ParseDeleteURL(rawURL)
	if err != nil {
		return err
	}

	serverOrigin, apiOrigin, err := overrideOrigins(dl.Origin, serverFlag, apiFlag)
	if err != nil {
		return err
	}
	c, err := a.newClient(serverOrigin, apiOrigin)
	if err != nil {
		return err
	}
	list, err := c.ListRecipients(ctx, dl)
	if err != nil {
		return err
	}

	if jsonOut {
		return a.writeJSON(map[string]any{
			"id":         dl.ID,
			"recipients": list,
		})
	}
	for _, r := range list {
		limitStr := "unlimited"
		if r.MaxOpens != nil {
			limitStr = strconv.Itoa(*r.MaxOpens)
		}
		status := "active"
		if r.Revoked {
			status = "revoked"
		} else if r.MaxOpens != nil && r.Opens >= *r.MaxOpens {
			status = "exhausted"
		}
		fmt.Fprintf(a.Stdout, "index=%d (Link %d): opens=%d/%s status=%s\n", r.Index, r.Index+1, r.Opens, limitStr, status)
	}
	return nil
}

func (a *App) runRecipientsRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("recipients revoke", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		urlStdin   bool
		serverFlag string
		apiFlag    string
		jsonOut    bool
	)
	fs.BoolVar(&urlStdin, "url-stdin", false, "Read delete URL from stdin")
	fs.StringVar(&serverFlag, "server", "", "Override server origin from the delete URL")
	fs.StringVar(&apiFlag, "api", "", "Explicit API origin for split deployments")
	fs.BoolVar(&jsonOut, "json", false, "Output machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var rawURL, idxStr string
	var err error
	if urlStdin {
		if fs.NArg() != 1 {
			return errors.New("usage: nullbin-cli recipients revoke --url-stdin [flags] <index>")
		}
		rawURL, err = tty.ReadURLLine(a.stdinReader())
		if err != nil {
			return err
		}
		idxStr = fs.Arg(0)
	} else {
		if fs.NArg() != 2 {
			return errors.New("usage: nullbin-cli recipients revoke [flags] <delete-url> <index>")
		}
		rawURL = fs.Arg(0)
		idxStr = fs.Arg(1)
	}

	index, err := strconv.Atoi(idxStr)
	if err != nil || index < 0 {
		return fmt.Errorf("invalid recipient index %q (0-based integer required)", idxStr)
	}
	dl, err := link.ParseDeleteURL(rawURL)
	if err != nil {
		return err
	}

	serverOrigin, apiOrigin, err := overrideOrigins(dl.Origin, serverFlag, apiFlag)
	if err != nil {
		return err
	}
	c, err := a.newClient(serverOrigin, apiOrigin)
	if err != nil {
		return err
	}
	if err := c.RevokeRecipient(ctx, dl, index); err != nil {
		return err
	}

	if jsonOut {
		return a.writeJSON(map[string]any{
			"id":      dl.ID,
			"index":   index,
			"revoked": true,
		})
	}
	fmt.Fprintf(a.Stdout, "Revoked recipient %d on paste %s\n", index, dl.ID)
	return nil
}

func (a *App) runVersion(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		serverFlag string
		apiFlag    string
		jsonOut    bool
	)
	fs.StringVar(&serverFlag, "server", "", "Query server version at this origin")
	fs.StringVar(&apiFlag, "api", "", "Explicit API origin for split deployments")
	fs.BoolVar(&jsonOut, "json", false, "Output machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("unexpected positional arguments")
	}

	protocolInfo := map[string]any{
		"api":        client.APIVersion,
		"blob_write": int(format.Version),
		"blob_read":  []int{int(format.VersionUnpadded), int(format.Version)},
	}

	if serverFlag == "" {
		if jsonOut {
			return a.writeJSON(map[string]any{
				"cli_version": a.Build.Version,
				"protocol":    protocolInfo,
			})
		}
		fmt.Fprintf(a.Stdout, "nullbin-cli %s\n", a.Build.Version)
		fmt.Fprintf(a.Stdout, "Protocol:    API %s, blob v%d (v%d read-only)\n", client.APIVersion, format.Version, format.VersionUnpadded)
		return nil
	}

	serverOrigin, err := link.ValidateOrigin(serverFlag)
	if err != nil {
		return fmt.Errorf("invalid --server origin: %w", err)
	}
	apiOrigin := ""
	if apiFlag != "" {
		apiOrigin, err = link.ValidateOrigin(apiFlag)
		if err != nil {
			return fmt.Errorf("invalid --api origin: %w", err)
		}
	}

	c, err := a.newClient(serverOrigin, apiOrigin)
	if err != nil {
		return err
	}
	info, err := c.ServerVersion(ctx)
	if err != nil {
		return err
	}

	if jsonOut {
		return a.writeJSON(map[string]any{
			"cli_version": a.Build.Version,
			"protocol":    protocolInfo,
			"server":      info,
		})
	}
	fmt.Fprintf(a.Stdout, "nullbin-cli %s\n", a.Build.Version)
	fmt.Fprintf(a.Stdout, "Protocol:    API %s, blob v%d (v%d read-only)\n", client.APIVersion, format.Version, format.VersionUnpadded)
	fmt.Fprintf(a.Stdout, "Server:      %s (API: %s)\n", info.SiteOrigin, info.APIOrigin)
	if info.SiteVersion != "" {
		fmt.Fprintf(a.Stdout, "Site:        %s\n", info.SiteVersion)
	}
	if info.APIVersion != "" {
		fmt.Fprintf(a.Stdout, "API:         %s (%s)\n", info.APIVersion, info.APIMode)
	}
	return nil
}

func (a *App) readSingleURL(urlStdin bool, posArgs []string, usage string) (string, error) {
	if urlStdin {
		if len(posArgs) > 0 {
			return "", errors.New("unexpected positional arguments when --url-stdin is set")
		}
		return tty.ReadURLLine(a.stdinReader())
	}
	if len(posArgs) != 1 {
		return "", errors.New(usage)
	}
	return posArgs[0], nil
}

func overrideOrigins(urlOrigin, serverFlag, apiFlag string) (string, string, error) {
	serverOrigin := urlOrigin
	var err error
	if serverFlag != "" {
		serverOrigin, err = link.ValidateOrigin(serverFlag)
		if err != nil {
			return "", "", fmt.Errorf("invalid --server origin: %w", err)
		}
	}
	apiOrigin := ""
	if apiFlag != "" {
		apiOrigin, err = link.ValidateOrigin(apiFlag)
		if err != nil {
			return "", "", fmt.Errorf("invalid --api origin: %w", err)
		}
	}
	return serverOrigin, apiOrigin, nil
}
