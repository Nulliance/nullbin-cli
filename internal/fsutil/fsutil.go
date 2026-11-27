// Package fsutil provides safe, verify-before-commit file output and safe
// local file input helpers for nullbin-cli.
package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Nulliance/nullbin-cli/client"
	"github.com/Nulliance/nullbin-cli/format"
)

// OpenLocalFile validates that path is a regular readable file and returns a
// client.FileInput ready for streaming encryption.
func OpenLocalFile(path string) (client.FileInput, error) {
	info, err := os.Stat(path)
	if err != nil {
		return client.FileInput{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return client.FileInput{}, fmt.Errorf("%s is not a regular file", path)
	}
	mimeType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if idx := strings.IndexByte(mimeType, ';'); idx >= 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}
	return client.FileInput{
		Name: filepath.Base(path),
		MIME: mimeType,
		Size: info.Size(),
		Open: func() (io.ReadCloser, error) {
			return os.Open(path)
		},
	}, nil
}

// ResolveOutputPath determines the safe destination path for an attachment.
// When explicitOut is non-empty it is used directly; otherwise suggestedName is
// strictly sanitized with format.CleanFileName and placed inside outDir.
func ResolveOutputPath(outDir, suggestedName, explicitOut string) (string, error) {
	if explicitOut != "" {
		return explicitOut, nil
	}
	if outDir == "" {
		outDir = "."
	}
	safeName := format.CleanFileName(suggestedName, "download")
	if safeName == "." || safeName == ".." || strings.ContainsAny(safeName, `/\`) {
		return "", errors.New("unsafe output filename")
	}
	return filepath.Join(outDir, safeName), nil
}

// SaveVerifiedStream streams decrypted attachment bytes into a private (0600)
// temporary file in the destination directory and atomically commits it to
// destPath ONLY after r reaches io.EOF cleanly (meaning TAG_FINAL, zero
// padding, and absence of trailing bytes have all been verified).
//
// On any error, the temporary file is removed and destPath is untouched.
// Existing destinations are never overwritten unless force is true; symlinks
// and directories at destPath are always refused.
func SaveVerifiedStream(destPath string, force bool, r io.Reader) (int64, error) {
	if err := checkDestination(destPath, force); err != nil {
		return 0, err
	}

	dir := filepath.Dir(destPath)
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return 0, fmt.Errorf("destination directory %s: %w", dir, err)
	}
	if !dirInfo.IsDir() {
		return 0, fmt.Errorf("destination parent %s is not a directory", dir)
	}

	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return 0, err
	}
	tmpPath := filepath.Join(dir, ".nullbin-tmp-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("creating temporary file: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	written, err := io.Copy(f, r)
	if err != nil {
		return 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, fmt.Errorf("syncing temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("closing temporary file: %w", err)
	}

	// Re-check destination right before commit.
	if err := checkDestination(destPath, force); err != nil {
		return 0, err
	}

	if !force && runtime.GOOS != "windows" {
		// Atomic no-clobber commit on POSIX.
		if err := os.Link(tmpPath, destPath); err != nil {
			return 0, fmt.Errorf("committing %s: %w", destPath, err)
		}
		_ = os.Remove(tmpPath)
		committed = true
		return written, nil
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return 0, fmt.Errorf("committing %s: %w", destPath, err)
	}
	committed = true
	return written, nil
}

func checkDestination(destPath string, force bool) error {
	info, err := os.Lstat(destPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symbolic link %s", destPath)
	}
	if info.IsDir() {
		return fmt.Errorf("destination %s is a directory", destPath)
	}
	if !force {
		return fmt.Errorf("destination %s already exists (use --force to overwrite)", destPath)
	}
	return nil
}
