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

## Required before multi-user file access

Authentication alone is not sufficient. Every file, folder, version, share, export, search result, background job, cache lookup, transfer session, and administrative action must enforce authorization at the trusted backend boundary. Tests must include denied cross-user direct-object access.

## Private Spaces

Private Spaces are planned client-side encrypted storage. No zero-knowledge claim is authorized by this foundation. A future implementation requires reviewed key generation, wrapping, device enrollment, sharing, recovery, rotation, revocation, metadata-minimization, and cryptographic versioning.

## Production boundary

Green CI does not establish production readiness. Target-environment validation, recovery, observability, accessibility, integration and exact-candidate security evidence remain separate gates.
