# nullbin-cli

The official command-line client and Go library for [**Nullbin**](https://github.com/Nulliance/nullbin-server), a zero-knowledge encrypted pastebin.

Nullbin's priorities are, in order: **security, then simplicity**.

## Security Highlights

- **Zero-knowledge, client-side only:** All encryption, decryption, Argon2id key stretching, BLAKE2b subkey derivation, Padmé padding, and multi-file ZIP packing happen locally. The server only ever sees ciphertext and derived capability tokens.
- **Eliminates browser JS trust (R1):** Unlike a web browser loading frontend JavaScript on every visit, a locally built/verified `nullbin-cli` binary runs audited, pinned cryptographic code — even if the remote frontend host or CDN is compromised.
- **100% protocol compatible** with `Nulliance/nullbin-server` (libsodium `crypto_secretstream_xchacha20poly1305`, BLAKE2b-256 KDF, Argon2id `OPSLIMIT_MODERATE`/`MEMLIMIT_MODERATE` with Unicode NFC normalization, blob v2 with Padmé padding, legacy blob v1 read-only support, deterministic stored ZIP archives, burn-after-reading, and separate recipient links).
- **Decentralized & fail-closed:** No default public server is hardcoded. You must explicitly choose a target instance via `--server`, `NULLBIN_SERVER`, or `~/.config/nullbin/config.json` (mode `0600`).
- **Hardened CLI:**
  - Never accepts plaintext passwords in CLI arguments (`argv`); passwords come only from interactive TTY prompts (echo off), `--password-stdin`, `--password-fd`, or `--generate-password`.
  - Supports `--url-stdin` so `#key` and `#d.<delete-token>` fragments do not appear in process listings or shell history.
  - Strictly enforces HTTPS (plain HTTP allowed only for `localhost`, `127.0.0.1`, `[::1]`), disables all HTTP redirects, sends no cookies or `Referer`, and bounds all JSON/prefix/error reads.
  - Verifies `TAG_FINAL`, zero-padding, and EOF before atomically committing decrypted attachments from a private `0600` temporary file.
  - Escapes ANSI/C0/C1 terminal control sequences and warns on hidden/bidirectional (Trojan Source) characters when printing to an interactive TTY.
- **Minimal dependencies:** Go standard library + `golang.org/x/crypto`, `golang.org/x/term`, and `golang.org/x/text` only.

## Installation

### Build from source (recommended)

```bash
git clone https://github.com/Nulliance/nullbin-cli.git
cd nullbin-cli
CGO_ENABLED=0 go build -trimpath -o nullbin-cli ./cmd/nullbin-cli
```

Or with Go 1.25+:

```bash
go install github.com/Nulliance/nullbin-cli/cmd/nullbin-cli@latest
```

### Verify a release binary

Official releases include `SHA256SUMS` and a keyless Sigstore Cosign bundle (`SHA256SUMS.sigstore.json`):

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Nulliance/nullbin-cli/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

## Server Configuration

`nullbin-cli` never defaults to any public server. Configure your target instance using one of:

1. Flag: `--server https://paste.example.com` (optional `--api https://api.example.com` for split deployments; if omitted, `api_origin` is discovered via `GET <server>/version.json`).
2. Environment: `export NULLBIN_SERVER=https://paste.example.com` (optional `NULLBIN_API`).
3. Config file: `~/.config/nullbin/config.json` (on POSIX systems, permissions must be `0600`):

```json
{
  "server": "https://paste.example.com"
}
```

For `read`, `delete`, and `recipients`, the server origin is inferred automatically from the paste or delete URL unless overridden with `--server`.

## CLI Usage

### Create a paste

```bash
# From stdin
echo "top secret" | nullbin-cli create --server https://paste.example.com --expires 1h

# With interactive password prompt (echo off, never in argv) and burn after reading
nullbin-cli create --server https://paste.example.com --text "one-time secret" --burn --password

# With a locally generated 20-character password and JSON output for scripts
nullbin-cli create --server https://paste.example.com --file report.pdf --generate-password --json

# Attach multiple files (2..100 files packed into a deterministic stored ZIP)
nullbin-cli create --server https://paste.example.com --file a.txt --file b.bin --expires 7d

# Create separate per-recipient links with per-link open limits
nullbin-cli create --server https://paste.example.com --text "team credentials" --recipient-limits 1,3,none
```

### Read a paste

```bash
# Read from URL passed on stdin (keeps #key out of argv / ps / shell history)
printf '%s\n' 'https://paste.example.com/p/<id>#<key>' | nullbin-cli read --url-stdin

# Read a burn paste non-interactively and save attachment safely into ./downloads
nullbin-cli read --yes --out-dir ./downloads 'https://paste.example.com/p/<id>#<key>.b'

# Read a password-protected paste from a file descriptor
nullbin-cli read --password-fd 3 'https://paste.example.com/p/<id>#<key>' 3< /path/to/passfile

# Raw unmodified bytes (disables TTY ANSI/bidi escaping)
nullbin-cli read --raw 'https://paste.example.com/p/<id>#<key>'
```

### Delete a paste

```bash
printf '%s\n' 'https://paste.example.com/d/<id>#d.<token>' | nullbin-cli delete --url-stdin
```

### Manage separate recipient links

```bash
# List open counts and revocation status
printf '%s\n' 'https://paste.example.com/d/<id>#d.<token>.r' | nullbin-cli recipients list --url-stdin

# Revoke recipient index 1 (0-based)
printf '%s\n' 'https://paste.example.com/d/<id>#d.<token>.r' | nullbin-cli recipients revoke --url-stdin 1
```

### Version

```bash
nullbin-cli version
nullbin-cli version --server https://paste.example.com
```

## Go Library Usage

Embed Nullbin directly in Go applications via `github.com/Nulliance/nullbin-cli/client` and `github.com/Nulliance/nullbin-cli/link`:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Nulliance/nullbin-cli/client"
	"github.com/Nulliance/nullbin-cli/link"
)

func main() {
	ctx := context.Background()
	c, err := client.New("https://paste.example.com")
	if err != nil {
		log.Fatal(err)
	}

	created, err := c.Create(ctx, client.CreateOptions{
		Text:      "hello from Go",
		ExpiresIn: 3600,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Share:", created.ViewURL)

	vl, err := link.ParseViewURL(created.ViewURL)
	if err != nil {
		log.Fatal(err)
	}
	defer vl.Close()

	opened, err := c.Read(ctx, vl, client.ReadOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer opened.Close()
	fmt.Println("Decrypted:", opened.Meta.Text)
}
```

## License

Licensed under **AGPL-3.0-only** (matching `Nulliance/nullbin-server`). See [LICENSE](LICENSE).
