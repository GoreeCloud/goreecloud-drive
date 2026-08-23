# Storage Model

GoreeCloud Drive separates user payload authority from application infrastructure.

## Logical layers

1. **Final objects** — immutable or content-addressable file-version payloads on durable storage.
2. **Staging** — bounded temporary storage for resumable transfer assembly and verification.
3. **Trash** — logical recovery state; never treated as a backup.
4. **PostgreSQL metadata** — accounts, Spaces, memberships, nodes, versions, shares, upload sessions, quotas, activity and Sync bindings.
5. **Derived data** — previews, thumbnails, indexes and caches that can be regenerated.

The local backend in Milestone 0 creates `objects`, `staging`, and `trash` directories for development only. It is not the approved production TrueNAS layout.

## Finalization contract

Future upload code must verify expected length and checksum, fsync where required by the selected storage backend, atomically publish the finalized payload, then commit metadata so a partial transfer cannot masquerade as a complete file.

## Authority rule

Version history, Trash, sync replicas and caches do not replace Everkeep/Backup. Every important dataset has one authoritative source and an independent recovery path.
