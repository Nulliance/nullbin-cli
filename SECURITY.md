# Security Policy

`nullbin-cli` is security software. Thank you for helping keep it safe.

## Reporting a Vulnerability

**Email [hi@jacobzymet.com](mailto:hi@jacobzymet.com). Never open a public issue, discussion, or pull request for a security vulnerability.**

Please include:
- A clear description of the vulnerability and its impact.
- Reproduction steps or a proof of concept.
- Never include real paste links, keys, passwords, or third-party data; use test pastes only.

What to expect:
- Acknowledgement within 7 days.
- Assessment and remediation plan (or follow-up questions) within 14 days.
- Coordinated disclosure once a fix is ready, with credit in the advisory if desired.

## Scope

In scope: anything that breaks the guarantees in [THREAT_MODEL.md](THREAT_MODEL.md), including:
- Cryptographic or protocol flaws breaking confidentiality, authenticity, or interoperability with `Nulliance/nullbin-server`.
- Key, password, or capability token leakage (in `argv`, logs, error messages, HTTP redirects, or network requests).
- Undetected ciphertext tampering, truncation, trailing bytes, or non-zero padding acceptance.
- Committing unverified attachment bytes to disk, path traversal, symlink following, or filename sanitization bypasses.
- Terminal escape injection or Trojan Source bypasses on interactive TTY output.
- Origin validation, HTTPS enforcement, or config permission check bypasses.
- Non-reproducible release artifacts or CI/supply-chain weaknesses.

Out of scope: server-visible metadata (padded size, timing, IPs), compromised local endpoints, and secrets intentionally passed as positional URL arguments when `--url-stdin` was not used.

## Supported Versions

Only the latest release receives security fixes.
