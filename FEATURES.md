# Features

This record distinguishes implemented source from approved product direction so unfinished work is never presented as available.

## Implemented in Milestone 0

- Development Go HTTP service with graceful shutdown.
- `/healthz`, `/readyz`, and versioned `/api/v1/status` endpoints.
- Loopback-only default binding with explicit public-bind opt-in.
- Restrictive browser security headers and privacy-safe structured request logging.
- Development storage boundary with separate objects, staging, and trash directories.
- PostgreSQL foundation schema for accounts, Spaces, memberships, nodes, file versions, shares, upload sessions, favorites, activity, quotas, and Sync bindings.
- OpenAPI foundation contract.
- Responsive Glaze UI foundation shell with accessible focus, reduced-motion, reduced-transparency, empty/unavailable feature communication, and real service-health feedback.
- Automated Go formatting, vetting, and tests in CI.

## Planned

- GoreeCloud Identity authentication and session enforcement.
- Personal, shared, and Private Spaces.
- Owner, Manager, Editor, Contributor, Commenter, Viewer, and Drop-only roles.
- Resumable chunked upload/download with checksums and atomic finalization.
- Version history, Trash, favorites, activity, quotas, previews, search, and comments.
- User/group shares, guest links, expiration, passphrases, revocation, access limits, and file requests.
- Linux/Debian and Android clients with offline pinning, selective sync, and conflict visibility.
- Migration Mode for filesystem, Google Drive, Dropbox, and Nextcloud sources.
- Everkeep/Backup recovery integration and operational evidence.
