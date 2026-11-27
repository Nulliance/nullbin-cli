// Package fsutil provides safe, verify-before-commit file output (confined with
// os.Root) and TOCTOU-checked local file input helpers for nullbin-cli.
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
// client.FileInput ready for streaming encryption. Each open re-verifies that
// the opened descriptor is the same regular file (defending against TOCTOU
// swaps to FIFOs, devices, or symlinks).
func OpenLocalFile(path string) (client.FileInput, error) {
	initialInfo, err := os.Stat(path)
	if err != nil {
		return client.FileInput{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if !initialInfo.Mode().IsRegular() {
		return client.FileInput{}, fmt.Errorf("%s is not a regular file", path)
	}
	mimeType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if idx := strings.IndexByte(mimeType, ';'); idx >= 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}
	return client.FileInput{
		Name: filepath.Base(path),
		MIME: mimeType,
		Size: initialInfo.Size(),
		Open: func() (io.ReadCloser, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			fi, err := f.Stat()
			if err != nil {
				_ = f.Close()
				return nil, err
			}
			if !fi.Mode().IsRegular() || !os.SameFile(initialInfo, fi) {
				_ = f.Close()
				return nil, fmt.Errorf("%s changed while opening", path)
			}
			return f, nil
		},
	}, nil
}

// ResolveOutputPath determines the safe destination path for an attachment.
// When explicitOut is non-empty it is used directly; otherwise suggestedName is
// strictly sanitized with format.CleanFileName and placed inside outDir.
func ResolveOutputPath(outDir, suggestedName, explicitOut string) (string, error) {
	if explicitOut != "" {
		if strings.HasSuffix(explicitOut, string(os.PathSeparator)) || strings.HasSuffix(explicitOut, "/") {
			return "", errors.New("output path must name a file, not a directory")
		}
		base := filepath.Base(explicitOut)
		if base == "" || base == "." || base == ".." {
			return "", errors.New("unsafe output filename")
		}
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
// temporary file inside an os.Root opened on the destination directory, and
// atomically commits it to destPath ONLY after r reaches io.EOF cleanly
// (meaning TAG_FINAL, zero padding, and absence of trailing bytes have all
// been verified).
//
// On any error, the temporary file is removed and destPath is untouched.
// Existing destinations are never overwritten unless force is true; symlinks
// and directories at destPath are always refused.
func SaveVerifiedStream(destPath string, force bool, r io.Reader) (int64, error) {
	dir := filepath.Dir(destPath)
	base := filepath.Base(destPath)
	if base == "" || base == "." || base == ".." || strings.ContainsAny(base, `/\`) {
		return 0, errors.New("unsafe destination filename")
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, fmt.Errorf("opening destination directory %s: %w", dir, err)
	}
	defer root.Close()

	if err := checkRootDestination(root, base, destPath, force); err != nil {
		return 0, err
	}

	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return 0, err
	}
	tmpName := ".nullbin-tmp-" + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("creating temporary file: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = root.Remove(tmpName)
		}
	}()

	copyBuf := make([]byte, 64*1024)
	defer clear(copyBuf)
	written, err := io.CopyBuffer(f, r, copyBuf)
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
	if err := checkRootDestination(root, base, destPath, force); err != nil {
		return 0, err
	}

	if runtime.GOOS == "windows" {
		if err := os.Rename(filepath.Join(dir, tmpName), filepath.Join(dir, base)); err != nil {
			return 0, fmt.Errorf("committing %s: %w", destPath, err)
		}
		committed = true
		return written, nil
	}

	if !force {
		// Atomic no-clobber commit on POSIX inside os.Root.
		if err := root.Link(tmpName, base); err != nil {
			return 0, fmt.Errorf("committing %s: %w", destPath, err)
		}
		_ = root.Remove(tmpName)
		committed = true
		return written, nil
	}

	if err := root.Rename(tmpName, base); err != nil {
		return 0, fmt.Errorf("committing %s: %w", destPath, err)
	}
	committed = true
	return written, nil
}

func checkRootDestination(root *os.Root, base, displayPath string, force bool) error {
	info, err := root.Lstat(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symbolic link %s", displayPath)
	}
	if info.IsDir() {
		return fmt.Errorf("destination %s is a directory", displayPath)
	}
	if !force {
		return fmt.Errorf("destination %s already exists (use --force to overwrite)", displayPath)
	}
	return nil
}
