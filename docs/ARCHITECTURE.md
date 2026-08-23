# Architecture

GoreeCloud Drive is an original GoreeCloud-owned, multi-user file cloud. The authoritative product boundary is simple: **Drive owns files; Sync moves them.**

## Milestone 0 components

- `cmd/server`: development service entry point.
- `internal/httpapi`: versioned HTTP boundary, security headers, health/readiness and lifecycle status.
- `internal/config`: fail-closed runtime configuration.
- `internal/storage`: storage boundary separating finalized objects, staging, and trash.
- `migrations`: PostgreSQL ownership-first metadata model.
- `api`: first-party OpenAPI contract.
- `web`: Glaze UI foundation shell.

## Long-term boundaries

Identity authenticates users. Drive enforces file ownership and authorization. Sync owns transfer and replication workflows. Search may index Drive content only when the applicable security mode permits it. Everkeep and Backup protect recovery independently of Drive version history or Trash.

Standard Spaces keep ordinary portable files available to the server for authorized indexing, previews, collaboration, and administration. Private Spaces are a later client-side encrypted mode and must not be described as zero-knowledge until key management, recovery, metadata exposure, and cryptographic review are complete.

## Data authority

Finalized user payloads belong on approved durable TrueNAS datasets. Metadata belongs in PostgreSQL. Upload staging, previews, caches, and temporary processing are non-authoritative. Application configuration and secrets remain separate from user payloads.

## Current acceptance boundary

This repository is Development. Milestone 0 does not provide authentication, production file uploads, shared Spaces, Private Spaces, production deployment, or Stable acceptance.
