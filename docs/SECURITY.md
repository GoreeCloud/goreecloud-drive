# Security Architecture

GoreeCloud Drive follows Wardveil Security as a functional security integration boundary, not a decorative badge.

## Foundation controls

- Loopback-only bind by default; public binding requires an explicit environment opt-in.
- HTTP read, write, idle, header and shutdown limits.
- Restrictive browser security headers on all served content.
- Private runtime storage directories.
- Explicit versioned API boundary.
- No reusable credentials in source or examples.
- Capability status reports unfinished security-sensitive functionality as unavailable.

## Wardveil file-content boundary

The resumable-upload service now has a fail-closed Wardveil Scan gate before staged bytes can be finalized into Drive's active object namespace. The finding must be authoritative and bound to the exact `drive_file` resource identity and SHA-256 digest. A current clean result with evidence is required for release; suspicious, malicious, unknown, unsupported, stale, mismatched, or unavailable verification does not publish the object. Drive never connects directly to ClamAV.

See [`WARDVEIL-SCANNING.md`](WARDVEIL-SCANNING.md) for result semantics, Privacy Shield minimization, quarantine authority, Everkeep restore separation, and production acceptance requirements.

## Required before multi-user file access

Authentication alone is not sufficient. Every file, folder, version, share, export, search result, background job, cache lookup, transfer session, and administrative action must enforce authorization at the trusted backend boundary. Tests must include denied cross-user direct-object access.

## Private Spaces

Private Spaces are planned client-side encrypted storage. No zero-knowledge claim is authorized by this foundation. A future implementation requires reviewed key generation, wrapping, device enrollment, sharing, recovery, rotation, revocation, metadata-minimization, and cryptographic versioning.

## Production boundary

Green CI does not establish production readiness. Target-environment validation, recovery, observability, accessibility, integration and exact-candidate security evidence remain separate gates. The Wardveil source consumer therefore remains `unaccepted` for production runtime claims until deployed evidence satisfies the documented acceptance requirements.
