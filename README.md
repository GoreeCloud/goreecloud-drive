# GoreeCloud Drive

Privacy-first, multi-user self-hosted cloud storage and file-management platform for the GoreeCloud Suite.

> **Release lifecycle: Development.** This repository is not yet a Stable release or production-acceptance record.

GoreeCloud Drive is the first-party file-cloud experience for GoreeCloud. Its product boundary is **Drive owns files; Sync moves them.** Drive owns file/folder semantics, Spaces, ownership, authorization, sharing, versions, Trash, metadata, quotas, activity, search/preview policy, quarantine state, and the user-facing file experience. GoreeCloud Sync owns transfer and replication workflows between endpoints.

## Current foundation

The current foundation establishes:

- a Go HTTP service with safe defaults, health/readiness, structured logging, security headers, and graceful shutdown;
- an ownership-first PostgreSQL schema designed for multi-user accounts and Spaces;
- development storage separation for finalized objects, staging, Trash, and private quarantine state;
- resumable-upload service primitives with a fail-closed Wardveil Scan publication gate;
- exact `drive_file` resource and SHA-256 binding for Wardveil findings, with current authoritative clean evidence required before release;
- a Drive-owned quarantine target that durably claims an operation before isolation, moves payloads out of the active namespace, supports exact idempotent replay, and fails closed on conflicting or ambiguous state;
- an internal token-gated Drive quarantine HTTP boundary plus an internal-RPC-only Cloudflare target bridge with Workers.dev and preview URLs disabled;
- a manual exact-revision target deployment workflow with a non-mutating remote readback probe;
- a versioned first-party OpenAPI boundary;
- a responsive Glaze UI foundation shell that clearly marks unfinished capabilities;
- repository-local product, architecture, security, storage, contribution, and competitive-objective records;
- automated formatting, vetting, race-enabled tests, contract checks, coverage generation, and Cloudflare Worker type checking in CI.

Drive consumes Wardveil Security rather than connecting directly to ClamAV. Suspicious, malicious, unknown, unsupported, stale, mismatched, or unavailable scan evidence fails closed at the upload-finalization boundary. See [`docs/WARDVEIL-SCANNING.md`](docs/WARDVEIL-SCANNING.md).

Drive also remains authoritative for the actual isolation state of Drive files. Wardveil may authorize and coordinate quarantine, but the target operation is completed and read back through Drive's own storage boundary. See [`docs/WARDVEIL-QUARANTINE.md`](docs/WARDVEIL-QUARANTINE.md).

Authentication, production file operations, sharing, Sync transfers, Private Spaces, native clients, deployed Wardveil scanning transport, controlled production quarantine mutation/readback, production malware protection, production deployment, and Stable acceptance are **not** claimed by this source milestone.

## Quick start

Requirements: Go 1.25+.

```sh
make verify
make run
```

Then open `http://127.0.0.1:8080`.

The server intentionally binds to loopback by default. A non-loopback bind requires `GC_DRIVE_ALLOW_PUBLIC_BIND=true` and still does **not** authorize direct Internet exposure or production use. The internal Wardveil quarantine routes additionally remain unavailable unless `GC_DRIVE_WARDVEIL_SERVICE_TOKEN` is supplied through the runtime secret boundary.

## Repository map

- [`api/`](api/) — first-party API contract.
- [`cmd/server/`](cmd/server/) — service entry point.
- [`internal/`](internal/) — runtime configuration, HTTP, storage, upload, Wardveil scan-consumer, and Drive quarantine-target boundaries.
- [`cloudflare/quarantine-target/`](cloudflare/quarantine-target/) — Drive-owned internal Worker bridge and non-mutating deployment acceptance runner.
- [`contracts/wardveil.drive-file-scan.json`](contracts/wardveil.drive-file-scan.json) — Drive's source consumer contract for Wardveil Scan.
- [`contracts/wardveil.drive-quarantine-target.json`](contracts/wardveil.drive-quarantine-target.json) — Drive's resource-owner quarantine target contract.
- [`migrations/`](migrations/) — PostgreSQL schema evolution.
- [`web/`](web/) — Glaze UI foundation shell.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system and suite boundaries.
- [`docs/SECURITY.md`](docs/SECURITY.md) — security architecture.
- [`docs/WARDVEIL-SCANNING.md`](docs/WARDVEIL-SCANNING.md) — file-security integration and scan acceptance boundary.
- [`docs/WARDVEIL-QUARANTINE.md`](docs/WARDVEIL-QUARANTINE.md) — Drive-owned quarantine execution, Cloudflare bridge, and production-acceptance boundary.
- [`docs/STORAGE.md`](docs/STORAGE.md) — data authority and storage model.
- [`COMPETITIVE-OBJECTIVES.md`](COMPETITIVE-OBJECTIVES.md), [`FEATURES.md`](FEATURES.md), [`BENEFITS.md`](BENEFITS.md) — maintained product direction and capability records.
- [`artwork/`](artwork/) — canonical official-artwork location.

## Governing principles

- Multi-user isolation is designed in from the first schema.
- Security and privacy claims must reflect implemented controls and evidence.
- Drive remains authoritative for Drive file state even when Wardveil authorizes a security action.
- Quarantine is isolation, not deletion; release or destructive removal requires separate authority.
- Ordinary files remain portable and application-independent.
- Version history, Trash, quarantine copies, sync replicas, and caches are not backups.
- Everkeep remains the recovery, preservation, and restore-verification authority.
- No advertising or behavioral monetization is part of the product model.
- GoreeCloud-controlled APIs and export paths prevent unnecessary vendor lock-in.

## License

GNU Affero General Public License v3.0. See [`LICENSE`](LICENSE).
