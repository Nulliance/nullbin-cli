# nullbin-cli

The official command-line client and Go library for [Nullbin](https://github.com/Nulliance/nullbin-server).

Encrypts and decrypts pastes locally so you do not have to trust website JavaScript served by a remote host. Works with any Nullbin server and produces links identical to the web app.

For hosting a server, protocol specifications, and paste limits, see [`Nulliance/nullbin-server`](https://github.com/Nulliance/nullbin-server).

## Start here

| I want to… | Go to |
|---|---|
| Install `nullbin-cli` | [Install](#install) |
| Point it at my Nullbin server | [Choose a server](#choose-a-server) |
| Create, read, or delete pastes | [Using nullbin-cli](#using-nullbin-cli) |
| Embed Nullbin in a Go app | [Go library](#go-library) |
| Review CLI security guarantees | [CLI safety](#cli-safety) and [THREAT_MODEL.md](THREAT_MODEL.md) |
| Look up every command flag | [Flag reference](#flag-reference) |
| Report a security problem | [SECURITY.md](SECURITY.md) |
| Contribute or cut a release | [CONTRIBUTING.md](CONTRIBUTING.md) |
| See the license | [AGPL-3.0-only](LICENSE) |

## Install

**Build from source** (Go 1.25+):

```bash
git clone https://github.com/Nulliance/nullbin-cli.git
cd nullbin-cli
CGO_ENABLED=0 go build -trimpath -o nullbin-cli ./cmd/nullbin-cli
```

Or install directly with Go:

```bash
go install github.com/Nulliance/nullbin-cli/cmd/nullbin-cli@latest
```

<details>
<summary>Verify a published release binary</summary>

Download your platform binary, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` from the [Releases page](https://github.com/Nulliance/nullbin-cli/releases), then verify:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Nulliance/nullbin-cli/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

</details>

## Choose a server

`nullbin-cli` has **no default public server**. For `create`, specify your instance in one of three ways (checked in order):

1. Flag: `--server https://paste.example.com`
2. Environment variable: `export NULLBIN_SERVER=https://paste.example.com`
3. Config file at `~/.config/nullbin/config.json` (must be mode `0600` on Linux/macOS):

   ```json
   {
     "server": "https://paste.example.com"
   }
   ```

**Separate website and API hosts (Option B):** `nullbin-cli` discovers the API automatically from `<server>/version.json`, or you can pin it with `--api https://api.example.com` (or `NULLBIN_API` / `"api"` in `config.json`).

**Reading, deleting, and managing links:** `read`, `delete`, and `recipients` read the server address directly from the paste or delete URL.

HTTPS is required. Plain `http://` is allowed only for `localhost`, `127.0.0.1`, and `[::1]`.

## Using nullbin-cli

| Task | Command |
|---|---|
| Create from stdin | `echo "secret" \| nullbin-cli create --expires 1h` |
| Create with a password (prompt) | `nullbin-cli create --text "secret" --password` |
| Create with a generated password | `nullbin-cli create --text "secret" --generate-password` |
| Create a burn-after-reading paste | `nullbin-cli create --text "one-time" --burn` |
| Attach one or more files | `nullbin-cli create --file report.pdf --file notes.txt` |
| Create separate links per person | `nullbin-cli create --text "creds" --recipient-limits 1,3,none` |
| Read a paste (keeping `#key` out of `argv`) | `printf '%s\n' '<view-url>' \| nullbin-cli read --url-stdin` |
| Read a burn paste and save attachment | `nullbin-cli read --yes --out-dir ./downloads '<view-url>'` |
| Delete a paste | `printf '%s\n' '<delete-url>' \| nullbin-cli delete --url-stdin` |
| List or revoke separate links | `printf '%s\n' '<delete-url>' \| nullbin-cli recipients list --url-stdin` |
| Check CLI and server versions | `nullbin-cli version --server https://paste.example.com` |

Add `--json` to any command for machine-readable output on stdout (prompts and notices go to stderr).

### Passing passwords and URLs safely

`--password` never takes a value on the command line (so passwords never leak in `ps` or shell history):

- Interactive terminal: `--password` (prompts with echo off).
- Scripts / pipes: `--password-stdin` or `--password-fd 3` (`3< /path/to/passfile`).
- Keep `#key` and `#d.<token>` out of process listings with `--url-stdin`.

## CLI safety

- **No remote JS trust:** All crypto runs in your local binary.
- **Verify before saving:** Attachments decrypt into a private (`0600`) temporary file and are renamed into place only after full stream authentication and zero-padding checks pass. Untrusted filenames are sanitized, and existing files are never overwritten without `--force`.
- **Safe terminal output:** On an interactive TTY, ANSI/control/bidi sequences are escaped and hidden characters (Trojan Source) trigger a warning on stderr. Pass `--raw` (or pipe stdout) for unmodified bytes.
- **No accidental burns:** Opening a burn paste or limited recipient link prompts on a TTY and refuses non-interactively unless `--yes` is given.
- **Strict transport:** HTTPS-only (except loopback), no HTTP redirects, no cookies or `Referer`, and bounded reads.

For the full analysis, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Go library

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
	fmt.Println(opened.Meta.Text)
}
```

## Flag reference

<details>
<summary>All commands and flags</summary>

### `create`

| Flag | Description |
|---|---|
| `--text <string>` | Paste text (otherwise reads stdin) |
| `--file <path>` | Attach a file (repeatable, up to 100 files) |
| `--expires <dur>` | `5m`, `30m`, `1h`, `3h`, `12h`, `1d` (default), `3d`, `7d`, `30d` |
| `--burn` | Burn after reading |
| `--max-reads <N>` | Open limit (`1`–`1000`) for `--burn` or `--recipients` |
| `--recipients <N>` | Create `N` separate links (`2`–`20`) |
| `--recipient-limits <csv>` | Per-link open limits (e.g. `1,3,none`) |
| `--discussion` | Enable encrypted comments (not with `--burn` or recipients) |
| `--password` | Prompt interactively on TTY (echo off) |
| `--password-stdin` | Read password from first line of stdin |
| `--password-fd <N>` | Read password from open file descriptor `N` |
| `--generate-password` | Generate a 20-character random password locally |
| `--server <origin>` | Target Nullbin server origin |
| `--api <origin>` | Explicit API origin (overrides `/version.json`) |
| `--json` | JSON output |

### `read [url]`

| Flag | Description |
|---|---|
| `--url-stdin` | Read paste URL from stdin |
| `--out <path>` | Write attachment to this exact path |
| `--out-dir <dir>` | Write attachment into directory using sanitized filename |
| `--force` | Overwrite existing regular output file |
| `--raw` | Print raw bytes without TTY escaping |
| `--yes` | Confirm consuming a burn/limited link without prompting |
| `--password`, `--password-stdin`, `--password-fd <N>` | Password input |
| `--server <origin>`, `--api <origin>`, `--json` | Origin overrides and JSON output |

### `delete [delete-url]` and `recipients`

- `delete [--url-stdin] [--server <origin>] [--api <origin>] [--json] [delete-url]`
- `recipients list [--url-stdin] [--server <origin>] [--api <origin>] [--json] [delete-url]`
- `recipients revoke [--url-stdin] [--server <origin>] [--api <origin>] [--json] [delete-url] <index>` (0-based index)
- `version [--server <origin>] [--api <origin>] [--json]`

</details>
