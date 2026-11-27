# nullbin-cli Threat Model

This document describes the security boundaries, assets, adversaries, mitigations, and residual risks specific to **`nullbin-cli`** (the CLI binary and Go library). For server-side and web-frontend threat modeling, see [`Nulliance/nullbin-server`'s THREAT_MODEL.md](https://github.com/Nulliance/nullbin-server/blob/main/THREAT_MODEL.md).

## 1. Key Security Advantage Over the Browser: Eliminating R1

In Nullbin's browser threat model, **R1 (Malicious frontend JavaScript)** is the primary residual trust assumption: whoever controls the frontend host, DNS, or CDN can serve modified JavaScript that exfiltrates keys or plaintext before encryption/decryption.

**`nullbin-cli` eliminates R1** when the user installs a verified or self-built binary:
- All cryptographic code (`crypto/`, `format/`, `link/`) is compiled locally into the binary and never fetched from the server.
- A compromised or hostile Nullbin server (A5) cannot inject or modify client-side cryptographic logic.
- Even on split deployments (Option B), `GET <server>/version.json` is strictly bounded, parsed as data only, and its `api_origin` is validated against canonical HTTPS origin rules (never downgraded to HTTP, never followed across redirects).

## 2. Trust Boundaries & Adversaries

| Component / Actor | Trust |
|---|---|
| Local OS, user account, terminal emulator | Trusted to execute `nullbin-cli` faithfully; local multi-user process listings (`ps`) and shell history are treated as leaky surfaces (see §3). |
| Remote Nullbin server & API | **Untrusted** with plaintext, keys, passwords, filenames, or MIME types. Trusted only for availability, expiry, and burn/recipient open enforcement. May return malicious blobs, oversized responses, redirects, or crafted error strings. |
| Malicious paste author (A7) | May craft pastes containing ANSI/OSC terminal escape sequences, Trojan Source bidirectional/invisible Unicode characters, path-traversal filenames (`../../.bashrc`), Windows device names (`CON.txt`), non-zero padding, truncated streams, or oversized metadata. |
| Supply chain (A8) | Mitigated via minimal Go dependencies (`x/crypto`, `x/term`, `x/text` only), SHA-pinned GitHub Actions, reproducible builds, and keyless Sigstore signing. |

## 3. CLI-Specific Threats & Mitigations

### 3.1 Secret Exposure in `argv`, Process Lists, and Shell History
- **Threat:** Passing passwords or `#key` / `#d.<token>` URLs on the command line exposes secrets to local users via `ps` / `/proc/<pid>/cmdline` and persists them in `~/.bash_history` / `~/.zsh_history`.
- **Mitigations:**
  - `--password` is strictly a boolean flag; `nullbin-cli` **never** accepts a plaintext password in `argv` and rejects unexpected positional arguments on `create`.
  - Passwords are read only from an interactive TTY with echo disabled (`golang.org/x/term`), `--password-stdin`, `--password-fd <N>`, or generated locally with `--generate-password`.
  - `read`, `delete`, `recipients list`, and `recipients revoke` support `--url-stdin` so `#key` and `#d.<token>` never enter `argv`.
  - Secrets, keys, passwords, and capability tokens are never included in error messages or logs.

### 3.2 Memory Hygiene
- **Threat:** Key material or passwords lingering in heap buffers after use.
- **Mitigations:**
  - `fragmentKey`, `master`, `streamKey`, `commentKey`, `recipientSecrets`, secretstream key/nonce state, plaintext frame buffers, and password byte slices are explicitly zeroed via `clear(...)` immediately after use and in `defer`/`Close()` paths.
  - `DeriveMasterKey` allocates a fresh NFC buffer so caller-owned slices are never unexpectedly aliased or mutated.
- **Residual risk:** Go's garbage collector may copy stack frames or retain strings (such as CLI arguments or Go `string` paste text) until overwritten by subsequent allocations; swap/hibernation files are outside the CLI's control.

### 3.3 Terminal Injection & Trojan Source (A7)
- **Threat:** Untrusted paste text printed to a terminal may contain ANSI CSI/OSC escape sequences (e.g., OSC 52 clipboard write, window title manipulation, fake prompt spoofing via standalone `\r`) or bidirectional/invisible Unicode controls (CVE-2021-42574).
- **Mitigations:**
  - When stdout is an interactive TTY (unless `--raw` is explicitly passed), `SanitizeForTTY` strips 7-bit/8-bit CSI/OSC/DCS/APC/PM/SOS escape sequences and visibly escapes C0/C1 controls, standalone `\r`, and Unicode format/bidi characters.
  - `HasHiddenChars` detects Trojan Source / invisible / spoofed joiner characters (mirroring `nullbin-server/web/src/hidden.ts`) and emits a warning on stderr (and sets `hidden_chars_detected: true` in `--json` output).
  - Server API error messages are filtered against an explicit allowlist of known Nullbin error strings; unknown server error text is replaced with `HTTP <status>` so a hostile server cannot inject terminal escapes via error responses.

### 3.4 Attachment Extraction & Filesystem Attacks (A7)
- **Threat:** A malicious paste or tampered stream attempts to write partial/unverified bytes to disk, traverse directories (`../../`), disguise file extensions with bidi overrides (`invoice\u202Efdp.exe`), overwrite existing files or follow symlinks, or target Windows reserved device names (`CON`, `NUL`, `COM1`).
- **Mitigations:**
  - **Verify-before-commit:** Decrypted attachment bytes stream to a private (`0600`, `O_CREATE|O_EXCL`) temporary file in the destination directory and are atomically committed ONLY after `TAG_FINAL`, exact Padmé length, all-zero padding, and absence of trailing bytes are verified. Any failure deletes the temporary file immediately.
  - **Filename sanitization:** `format.CleanFileName` applies Unicode NFC, replaces path separators, drive-letter colons, control/bidi/default-ignorable runes, strips leading/trailing dots and spaces, caps length at 200 runes, and prefixes Windows device names with `_`.
  - **No clobber / no symlink follow:** Refuses to overwrite existing files unless `--force` is passed (using atomic `os.Link` no-clobber on POSIX), and always refuses overwriting symlinks or directories.

### 3.5 Transport, Discovery & Configuration Attacks (A1, A2, A5)
- **Threat:** MITM downgrade to HTTP, SSRF/redirect trickery leaking capability headers (`Nullbin-Upload-Token`, `Nullbin-Burn-Token`, `Nullbin-Delete-Token`), memory exhaustion via unbounded responses, or world-readable config tampering.
- **Mitigations:**
  - Fail-closed server selection (no hardcoded default server).
  - Strict HTTPS enforcement; plain `http://` is permitted only for `localhost`, `127.0.0.1`, and `[::1]`.
  - HTTP redirects are unconditionally disabled (`CheckRedirect` always returns an error), preventing capability tokens from ever being forwarded to another host.
  - No cookies (`Jar: nil`), no `Referer`, `Cache-Control: no-store`, TLS 1.2+ minimum, bounded JSON reads (128 KiB), exact 22-byte prefix reads, request timeouts, and 150-second download stall timeouts.
  - `version.json` discovery refuses HTTPS→HTTP downgrades and non-canonical origins.
  - `~/.config/nullbin/config.json` rejects symlinks, non-regular files, unknown JSON fields, and POSIX permissions looser than `0600`.

### 3.6 Accidental Burn Consumption
- **Threat:** Opening a burn-after-reading paste or limited recipient link unintentionally consumes an open (including in scripts or when a wrong password is entered).
- **Mitigations:**
  - On interactive TTYs, `read` peeks the public 22-byte `/prefix` (consuming no open) and prompts for explicit confirmation before calling `POST /read`. Non-TTY invocations fail closed unless `--yes` is passed.
  - For password-protected burn pastes, wrong passwords fail closed on the server without consuming an open; `nullbin-cli` re-checks `/prefix` to distinguish a wrong password from a missing/burned paste.

## 4. Residual Risks

- **Server metadata (R2):** The server still observes padded ciphertext size, timing, expiry, burn/recipient open counts, and client IP (use Tor / `HTTPS_PROXY` if network anonymity is required).
- **Interrupted burn downloads (R4):** Once `POST /read` authorizes a burn open, an interrupted network transfer consumes that open on the server.
- **Compromised local endpoint (R5):** Malware or a root attacker on the client machine can read terminal output, process memory, or saved files.
- **Argv usage when `--url-stdin` is omitted:** Passing a full paste URL as a positional argument places `#key` in `argv` for the duration of the command; use `--url-stdin` on shared hosts.
- **Go string/GC retention:** Go `string` values (e.g., decrypted paste text) are immutable and reclaimed by GC rather than explicitly zeroed.
