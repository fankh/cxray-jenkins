# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

Use GitHub's private vulnerability reporting on this repository:
**Security → Advisories → Report a vulnerability**.

We aim to acknowledge a report within 3 business days and to agree a remediation timeline after triage.
Please give us a reasonable window to release a fix before any public disclosure.

## Supported versions

Security fixes land on the latest released version (see [Releases](../../releases)).

## Security model

This plugin runs security gates inside Jenkins. Its own posture:

- **API URL is admin-only** (global config) — a job cannot redirect the access-key bearer.
- **Credential enumeration is permission-gated** on the form-fill endpoints.
- **Workspace reads reject** absolute paths and `..` traversal.
- The plugin **does not execute** the content it analyzes; it performs static analysis and calls the
  admin-configured CXRay API over TLS.
- Released `.hpi` artifacts carry a **SHA-256 checksum** and **SLSA build provenance** (GitHub attestations).

See [INTEGRATION.md](INTEGRATION.md) for the full model.
