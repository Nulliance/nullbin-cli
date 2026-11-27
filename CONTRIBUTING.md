# Contributing to nullbin-cli

Nullbin's priorities are, in order: **security, then simplicity**. When the two conflict, choose security, then the simpler option.

This repository is public; nothing may depend on source code secrecy. Never commit real secrets, paste links, keys, or capability tokens. All test fixtures use generated test data only.

## Changes Requiring Explicit Maintainer Review

Enforced by [CODEOWNERS](.github/CODEOWNERS):
- **Dependencies (`go.mod`, `go.sum`):** Runtime dependencies are strictly limited to the Go standard library plus `golang.org/x/crypto`, `golang.org/x/term`, and `golang.org/x/text`. Adding any new third-party module requires strong justification and maintainer approval.
- **Cryptography & framing (`crypto/`, `format/`, `link/`):** Any change touching key derivation, secretstream, Padmé padding, blob v2/v1 framing, ZIP packing, or URL/origin parsing.
- **HTTP client & CLI security controls (`client/`, `internal/`):** Transport hardening, redirect blocking, error allowlisting, secret input handling, TTY sanitization, config permissions, and verify-before-commit file extraction.
- **CI/CD & releases (`.github/`):** Workflow permissions, pinned SHA updates, security scans, and release signing.

## Rules of Thumb

- Keep code plain, auditable, and dependency-minimal (stdlib `flag`, `net/http`, `encoding/json`).
- Never hardcode a default public server.
- Never accept plaintext passwords in CLI flag values (`argv`).
- Never log or embed keys, passwords, or capability tokens in error messages.
- Pin all GitHub Actions to full 40-character commit SHAs and keep top-level `permissions: contents: read`. Never use `pull_request_target`.
- Update `THREAT_MODEL.md` and `README.md` whenever security behavior or CLI flags change.

## Before Opening a Pull Request

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
go test -run='^$' -fuzz='^FuzzParsePrefix$' -fuzztime=10s ./format
go test -run='^$' -fuzz='^FuzzDecodeBlob$' -fuzztime=10s ./format
go test -run='^$' -fuzz='^FuzzSanitizeFilename$' -fuzztime=10s ./format
go test -run='^$' -fuzz='^FuzzParseLink$' -fuzztime=10s ./link
```

## Releasing

Releases are cut manually from `main` via **Actions → Release → Run workflow** with a `vX.Y.Z` tag. The workflow verifies passing CI on `main`, builds all cross-platform binaries twice to confirm reproducibility, creates a keyless Sigstore-signed Git tag (Gitsign), signs `SHA256SUMS` with Cosign, and publishes the GitHub release.

Report security issues privately as described in [SECURITY.md](SECURITY.md).
