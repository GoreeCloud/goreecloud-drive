# GoreeCloud Drive

Privacy-first, multi-user self-hosted cloud storage and file-management platform for the GoreeCloud Suite.

> **Release lifecycle: Development.** This repository is not yet a Stable release or production-acceptance record.

GoreeCloud Drive is the first-party file-cloud experience for GoreeCloud. Its product boundary is **Drive owns files; Sync moves them.** Drive owns file/folder semantics, Spaces, ownership, authorization, sharing, versions, Trash, metadata, quotas, activity, search/preview policy, and the user-facing file experience. GoreeCloud Sync owns transfer and replication workflows between endpoints.

## Milestone 0

The current foundation establishes:

- a Go HTTP service with safe defaults, health/readiness, structured logging, security headers, and graceful shutdown;
- an ownership-first PostgreSQL schema designed for multi-user accounts and Spaces;
- development storage separation for finalized objects, staging, and Trash;
- a versioned first-party OpenAPI boundary;
- a responsive Glaze UI foundation shell that clearly marks unfinished capabilities;
- repository-local product, architecture, security, storage, contribution, and competitive-objective records;
- automated formatting, vetting, race-enabled tests, and coverage generation in CI.

Authentication, production file operations, sharing, Sync transfers, Private Spaces, native clients, production deployment, and Stable acceptance are **not** claimed by Milestone 0.

## Quick start

Requirements: Go 1.25+.

```sh
make verify
make run
```

Then open `http://127.0.0.1:8080`.

The server intentionally binds to loopback by default. A non-loopback bind requires `GC_DRIVE_ALLOW_PUBLIC_BIND=true` and still does **not** authorize direct Internet exposure or production use.

## Repository map

- [`api/`](api/) — first-party API contract.
- [`cmd/server/`](cmd/server/) — service entry point.
- [`internal/`](internal/) — runtime configuration, HTTP and storage boundaries.
- [`migrations/`](migrations/) — PostgreSQL schema evolution.
- [`web/`](web/) — Glaze UI foundation shell.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system and suite boundaries.
- [`docs/SECURITY.md`](docs/SECURITY.md) — security architecture.
- [`docs/STORAGE.md`](docs/STORAGE.md) — data authority and storage model.
- [`COMPETITIVE-OBJECTIVES.md`](COMPETITIVE-OBJECTIVES.md), [`FEATURES.md`](FEATURES.md), [`BENEFITS.md`](BENEFITS.md) — maintained product direction and capability records.
- [`artwork/`](artwork/) — canonical official-artwork location; final approved assets remain a release blocker until added.

## Governing principles

- Multi-user isolation is designed in from the first schema.
- Security and privacy claims must reflect implemented controls and evidence.
- Ordinary files remain portable and application-independent.
- Version history, Trash, sync replicas, and caches are not backups.
- No advertising or behavioral monetization is part of the product model.
- GoreeCloud-controlled APIs and export paths prevent unnecessary vendor lock-in.

## License

GNU Affero General Public License v3.0. See [`LICENSE`](LICENSE).
