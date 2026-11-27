package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Nulliance/nullbin-cli/client"
	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
	"github.com/Nulliance/nullbin-cli/format"
	"github.com/Nulliance/nullbin-cli/internal/fsutil"
	"github.com/Nulliance/nullbin-cli/internal/tty"
	"github.com/Nulliance/nullbin-cli/link"
)

func (a *App) runRead(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		urlStdin       bool
		outPath        string
		outDir         string
		force          bool
		rawOutput      bool
		yes            bool
		promptPassword bool
		passwordStdin  bool
		passwordFD     int
		serverFlag     string
		apiFlag        string
		jsonOut        bool
	)

	fs.BoolVar(&urlStdin, "url-stdin", false, "Read paste URL from stdin (avoids exposing #key in argv)")
	fs.StringVar(&outPath, "out", "", "Write decrypted attachment to this exact path")
	fs.StringVar(&outDir, "out-dir", "", "Write decrypted attachment into this directory using its sanitized filename")
	fs.BoolVar(&force, "force", false, "Allow overwriting an existing output file")
	fs.BoolVar(&rawOutput, "raw", false, "Output raw paste text without TTY ANSI/bidi sanitization")
	fs.BoolVar(&yes, "yes", false, "Confirm opening a burn-after-reading or limited recipient paste without prompting")
	fs.BoolVar(&promptPassword, "password", false, "Prompt interactively for password on TTY (echo off)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read password from the first line of stdin")
	fs.IntVar(&passwordFD, "password-fd", -1, "Read password from open file descriptor N")
	fs.StringVar(&serverFlag, "server", "", "Override server origin from the URL")
	fs.StringVar(&apiFlag, "api", "", "Explicit API origin for split deployments")
	fs.BoolVar(&jsonOut, "json", false, "Output machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if outPath != "" && outDir != "" {
		return errors.New("specify at most one of --out or --out-dir")
	}
	if urlStdin && passwordStdin {
		return errors.New("cannot use both --url-stdin and --password-stdin (use --password-fd or interactive TTY)")
	}

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
	if pwSources > 1 {
		return errors.New("choose at most one of --password, --password-stdin, or --password-fd")
	}

	var rawURL string
	var err error
	if urlStdin {
		if fs.NArg() > 0 {
			return errors.New("unexpected positional arguments when --url-stdin is set")
		}
		rawURL, err = tty.ReadURLLine(a.stdinReader())
		if err != nil {
			return err
		}
	} else {
		if fs.NArg() != 1 {
			return errors.New("usage: nullbin-cli read [flags] <paste-url> (or --url-stdin)")
		}
		rawURL = fs.Arg(0)
	}

	vl, err := link.ParseViewURL(rawURL)
	if err != nil {
		return err
	}
	defer vl.Close()

	// Infer server origin from the paste URL unless explicitly overridden.
	serverOrigin := vl.Origin
	apiOrigin := apiFlag
	if serverFlag != "" {
		serverOrigin, err = link.ValidateOrigin(serverFlag)
		if err != nil {
			return fmt.Errorf("invalid --server origin: %w", err)
		}
	}
	if apiOrigin != "" {
		apiOrigin, err = link.ValidateOrigin(apiOrigin)
		if err != nil {
			return fmt.Errorf("invalid --api origin: %w", err)
		}
	}

	var prePassword []byte
	defer func() {
		nbcrypto.Zero(prePassword)
	}()
	switch {
	case passwordStdin:
		prePassword, err = tty.ReadPasswordLine(a.stdinReader())
		if err != nil {
			return err
		}
	case passwordFD >= 0:
		prePassword, err = tty.ReadPasswordFD(passwordFD)
		if err != nil {
			return err
		}
	}

	var promptFn func(attempt int) ([]byte, error)
	if len(prePassword) == 0 && (promptPassword || a.stdinIsTTY()) {
		promptFn = func(attempt int) ([]byte, error) {
			if attempt >= 5 {
				return nil, &format.PasteError{Code: format.CodeWrongPassword, Message: "too many incorrect password attempts"}
			}
			label := "Password: "
			if attempt > 0 {
				label = "Incorrect password. Try again: "
			}
			return tty.PromptPassword(label, a.Stdin, a.Stderr)
		}
	}

	c, err := a.newClient(serverOrigin, apiOrigin)
	if err != nil {
		return err
	}

	readOpts := client.ReadOptions{
		Password:       prePassword,
		PasswordPrompt: promptFn,
	}
	if !yes && (vl.Burn || vl.RecipientSecret != nil) {
		readOpts.BeforeBurn = func(_ format.Prefix) error {
			ok, cerr := tty.ConfirmBurn(a.Stdin, a.Stderr, vl.RecipientSecret != nil)
			if cerr != nil {
				return cerr
			}
			if !ok {
				return &format.PasteError{Code: format.CodeCancelled, Message: "cancelled before consuming paste"}
			}
			return nil
		}
	}

	res, err := c.Read(ctx, vl, readOpts)
	if err != nil {
		return err
	}
	defer res.Close()

	// If attachment exists, verify-before-commit to disk before displaying anything.
	var savedPath string
	var savedBytes int64
	if res.File != nil {
		suggested := "download"
		if res.Meta.Filename != nil {
			suggested = *res.Meta.Filename
		}
		destPath, err := fsutil.ResolveOutputPath(outDir, suggested, outPath)
		if err != nil {
			return err
		}
		savedBytes, err = fsutil.SaveVerifiedStream(destPath, force, res.File)
		if err != nil {
			return fmt.Errorf("saving attachment: %w", err)
		}
		savedPath = destPath
	}

	hasHidden := tty.HasHiddenChars(res.Meta.Text)

	if jsonOut {
		out := struct {
			ID             string  `json:"id"`
			Type           string  `json:"type"`
			Text           string  `json:"text"`
			Filename       *string `json:"filename,omitempty"`
			Mime           *string `json:"mime,omitempty"`
			Size           int64   `json:"size"`
			SavedPath      string  `json:"saved_path,omitempty"`
			SavedBytes     int64   `json:"saved_bytes,omitempty"`
			Discussion     bool    `json:"discussion"`
			Password       bool    `json:"password_protected"`
			Burn           bool    `json:"burn"`
			ReadsRemaining *int    `json:"reads_remaining,omitempty"`
			ExpiresIn      *int    `json:"expires_in,omitempty"`
			HiddenChars    bool    `json:"hidden_chars_detected"`
		}{
			ID:             res.ID,
			Type:           res.Meta.Type,
			Text:           res.Meta.Text,
			Filename:       res.Meta.Filename,
			Mime:           res.Meta.Mime,
			Size:           res.Meta.Size,
			SavedPath:      savedPath,
			SavedBytes:     savedBytes,
			Discussion:     res.Meta.Discussion,
			Password:       res.HasPassword,
			Burn:           res.IsBurn,
			ReadsRemaining: res.ReadsRemaining,
			ExpiresIn:      res.ExpiresIn,
			HiddenChars:    hasHidden,
		}
		return a.writeJSON(out)
	}

	if hasHidden && a.stdoutIsTTY() {
		fmt.Fprintln(a.Stderr, "warning: paste text contains hidden, control, or bidirectional characters (possible Trojan Source)")
	}

	if res.Meta.Text != "" {
		outText := res.Meta.Text
		if a.stdoutIsTTY() && !rawOutput {
			sanitized, modified := tty.SanitizeForTTY(outText)
			if modified {
				fmt.Fprintln(a.Stderr, "notice: terminal control/bidi sequences were escaped for TTY safety (use --raw to print unmodified bytes)")
			}
			outText = sanitized
		}
		if _, err := io.WriteString(a.Stdout, outText); err != nil {
			return err
		}
		if a.stdoutIsTTY() && len(outText) > 0 && outText[len(outText)-1] != '\n' {
			_, _ = io.WriteString(a.Stdout, "\n")
		}
	}

	if savedPath != "" {
		fmt.Fprintf(a.Stderr, "Saved verified attachment (%d bytes) to %s\n", savedBytes, savedPath)
	}
	if res.ReadsRemaining != nil {
		if *res.ReadsRemaining == 0 {
			fmt.Fprintln(a.Stderr, "Notice: no opens remaining on this link.")
		} else {
			fmt.Fprintf(a.Stderr, "Notice: %d opens remaining.\n", *res.ReadsRemaining)
		}
	}
	return nil
}
