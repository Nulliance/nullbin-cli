package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Nulliance/nullbin-cli/client"
	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
	"github.com/Nulliance/nullbin-cli/format"
	"github.com/Nulliance/nullbin-cli/internal/fsutil"
	"github.com/Nulliance/nullbin-cli/internal/tty"
)

func (a *App) runCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		textFlag         string
		files            stringListFlag
		expiresFlag      string
		burn             bool
		maxReads         int
		recipientsCount  int
		recipientLimits  string
		discussion       bool
		promptPassword   bool
		passwordStdin    bool
		passwordFD       int
		generatePassword bool
		serverFlag       string
		apiFlag          string
		jsonOut          bool
	)

	fs.StringVar(&textFlag, "text", "", "Paste text (if omitted, reads text from stdin)")
	fs.Var(&files, "file", "Attach a file (repeatable, up to 100 files)")
	fs.StringVar(&expiresFlag, "expires", "1d", "Expiry duration: 5m, 30m, 1h, 3h, 12h, 1d, 3d, 7d, 30d")
	fs.BoolVar(&burn, "burn", false, "Burn after reading")
	fs.IntVar(&maxReads, "max-reads", 0, "Open limit for --burn or --recipients (1..1000)")
	fs.IntVar(&recipientsCount, "recipients", 0, "Create N separate recipient links (2..20)")
	fs.StringVar(&recipientLimits, "recipient-limits", "", "Comma-separated per-link open limits (e.g. 1,3,none)")
	fs.BoolVar(&discussion, "discussion", false, "Enable encrypted discussion comments")
	fs.BoolVar(&promptPassword, "password", false, "Prompt interactively for a password on TTY (echo off)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read password from the first line of stdin")
	fs.IntVar(&passwordFD, "password-fd", -1, "Read password from open file descriptor N")
	fs.BoolVar(&generatePassword, "generate-password", false, "Generate a strong 20-character password locally")
	fs.StringVar(&serverFlag, "server", "", "Target Nullbin server host or origin (https:// assumed; loopback http:// allowed)")
	fs.StringVar(&apiFlag, "api", "", "Explicit API origin for split deployments (overrides /version.json discovery)")
	fs.BoolVar(&jsonOut, "json", false, "Output machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("unexpected positional arguments (note: --password does not take a value on the command line)")
	}

	// Ensure at most one password source is selected.
	pwSources := 0
	if promptPassword {
		pwSources++
	}
	if passwordStdin {
		pwSources++
	}
	if passwordFD >= 0 {
		pwSources++
	}
	if generatePassword {
		pwSources++
	}
	if pwSources > 1 {
		return errors.New("choose at most one of --password, --password-stdin, --password-fd, or --generate-password")
	}

	expiresIn, err := client.ParseExpires(expiresFlag)
	if err != nil {
		return err
	}

	// Parse recipients specification.
	recipients, err := parseRecipientSpecs(recipientsCount, recipientLimits, burn, maxReads)
	if err != nil {
		return err
	}

	// Resolve server & API origin fail-closed before reading passwords or files.
	serverOrigin, apiOrigin, err := a.resolveServer(serverFlag, apiFlag)
	if err != nil {
		return err
	}

	// Open any attached files.
	if len(files) > format.MaxFiles {
		return fmt.Errorf("at most %d files may be attached", format.MaxFiles)
	}
	fileInputs := make([]client.FileInput, 0, len(files))
	for _, path := range files {
		fi, err := fsutil.OpenLocalFile(path)
		if err != nil {
			return err
		}
		fileInputs = append(fileInputs, fi)
	}

	// Determine paste text.
	text := textFlag
	if text == "" && !passwordStdin {
		if len(fileInputs) == 0 || !a.stdinIsTTY() {
			data, err := io.ReadAll(io.LimitReader(a.stdinReader(), format.MaxMetaBytes+1))
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
			if len(data) > format.MaxMetaBytes {
				return errors.New("paste text exceeds 16 MiB limit")
			}
			if !utf8.Valid(data) {
				clear(data)
				return errors.New("stdin contains invalid UTF-8 (attach binary data with --file)")
			}
			text = string(data)
			clear(data)
		}
	}
	if text == "" && len(fileInputs) == 0 {
		return errors.New("no paste content provided: pass --text, pipe stdin, or attach --file")
	}

	// Obtain password securely (never from argv).
	var password []byte
	defer func() {
		nbcrypto.Zero(password)
	}()

	switch {
	case promptPassword:
		password, err = tty.PromptNewPassword(a.Stdin, a.Stderr)
		if err != nil {
			return err
		}
	case passwordStdin:
		password, err = tty.ReadPasswordLine(a.stdinReader())
		if err != nil {
			return err
		}
		if err := nbcrypto.ValidateNewPassword(password); err != nil {
			return err
		}
	case passwordFD >= 0:
		password, err = tty.ReadPasswordFD(passwordFD)
		if err != nil {
			return err
		}
		if err := nbcrypto.ValidateNewPassword(password); err != nil {
			return err
		}
	case generatePassword:
		password, err = nbcrypto.GeneratePassword()
		if err != nil {
			return err
		}
	}

	c, err := a.newClient(serverOrigin, apiOrigin)
	if err != nil {
		return err
	}

	createOpts := client.CreateOptions{
		Text:       text,
		Files:      fileInputs,
		ExpiresIn:  expiresIn,
		Burn:       burn,
		MaxReads:   maxReads,
		Recipients: recipients,
		Discussion: discussion,
		Password:   password,
	}
	if len(recipients) > 0 {
		// Burn/maxReads have already been encoded per recipient.
		createOpts.Burn = false
		createOpts.MaxReads = 0
	}

	res, err := c.Create(ctx, createOpts)
	if err != nil {
		return err
	}

	if jsonOut {
		generatedPW := ""
		if generatePassword {
			generatedPW = string(password)
		}
		out := struct {
			*client.CreateResult
			GeneratedPassword string `json:"generated_password,omitempty"`
		}{
			CreateResult:      res,
			GeneratedPassword: generatedPW,
		}
		return a.writeJSON(out)
	}

	if len(res.RecipientURLs) > 0 {
		for i, u := range res.RecipientURLs {
			fmt.Fprintf(a.Stdout, "Recipient %d: %s\n", i+1, u)
		}
	} else {
		fmt.Fprintf(a.Stdout, "View URL:   %s\n", res.ViewURL)
	}
	fmt.Fprintf(a.Stdout, "Delete URL: %s\n", res.DeleteURL)
	if generatePassword && len(password) > 0 {
		_, _ = io.WriteString(a.Stdout, "Password:   ")
		_, _ = a.Stdout.Write(password)
		_, _ = io.WriteString(a.Stdout, "\n")
	}
	if !res.ExpiresAt.IsZero() {
		fmt.Fprintf(a.Stderr, "Expires at %s (%d encrypted bytes)\n", res.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"), res.TotalSize)
	}
	return nil
}

func parseRecipientSpecs(count int, limitsCSV string, burn bool, maxReads int) ([]client.RecipientSpec, error) {
	if count == 0 && limitsCSV == "" {
		return nil, nil
	}
	if limitsCSV != "" {
		parts := strings.Split(limitsCSV, ",")
		if count != 0 && count != len(parts) {
			return nil, fmt.Errorf("--recipients %d does not match %d entries in --recipient-limits", count, len(parts))
		}
		if len(parts) < client.MinRecipients || len(parts) > client.MaxRecipients {
			return nil, fmt.Errorf("--recipient-limits requires between %d and %d entries", client.MinRecipients, client.MaxRecipients)
		}
		specs := make([]client.RecipientSpec, len(parts))
		for i, raw := range parts {
			tok := strings.ToLower(strings.TrimSpace(raw))
			if tok == "" || tok == "none" || tok == "unlimited" || tok == "0" {
				continue
			}
			n, err := strconv.Atoi(tok)
			if err != nil || n < 1 || n > client.MaxBurnReads {
				return nil, fmt.Errorf("invalid recipient limit %q (use 1..%d or none)", raw, client.MaxBurnReads)
			}
			v := n
			specs[i].MaxReads = &v
		}
		return specs, nil
	}

	if count < client.MinRecipients || count > client.MaxRecipients {
		return nil, fmt.Errorf("--recipients must be between %d and %d", client.MinRecipients, client.MaxRecipients)
	}
	specs := make([]client.RecipientSpec, count)
	if burn || maxReads > 0 {
		limit := maxReads
		if limit == 0 {
			limit = 1
		}
		if limit < 1 || limit > client.MaxBurnReads {
			return nil, fmt.Errorf("--max-reads must be between 1 and %d", client.MaxBurnReads)
		}
		for i := range specs {
			v := limit
			specs[i].MaxReads = &v
		}
	}
	return specs, nil
}
