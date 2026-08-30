# Wardveil file-content scanning

GoreeCloud Drive consumes **Wardveil Scan** as its file-security boundary. Drive does not connect to ClamAV or any other malware engine directly; engine selection remains replaceable implementation detail behind Wardveil Security.

## Source integration

The current source milestone protects the resumable-upload publication boundary:

1. upload bytes remain in Drive's private staging namespace;
2. Drive computes the staged file SHA-256 digest and canonical identity `drive:<space_id>:file:<node_id>`;
3. the exact staged bytes and digest are presented to the injected Wardveil Scan client;
4. Drive validates the returned authoritative `scan_finding` against the expected resource identity, digest, evidence window, and result semantics;
5. a current clean finding with evidence references permits release;
6. Drive re-hashes staging after the scan and fails closed if the bytes changed;
7. only then may the existing atomic storage finalization publish the bytes into the active object namespace.

Scanner errors, stale or malformed evidence, scope mismatch, digest mismatch, `unknown`, and `unsupported` results do not publish the file.

## Development runtime wiring

The development server can opt into the real resumable-upload HTTP routes with the existing `StagedFileGate` and hardened signed Wardveil Scan client. This runtime path is disabled by default.

When `GC_DRIVE_UPLOADS_ENABLED=true`:

- the Scan endpoint is restricted by the client to explicit IPv4 loopback HTTP and the canonical `/v1/scan` path;
- Drive signs each Scan request with the configured caller/key identity and an owner-only credential file named by `GC_DRIVE_WARDVEIL_SCAN_SECRET_FILE`;
- the credential value is never required in `.env`, command arguments, shared evidence, or application logs;
- upload completion cannot publish content when the Scan credential, transport, evidence, or scanner path fails;
- the runtime uses the existing local staging/object backend and the development in-memory upload-session repository.

This is executable application-consumer wiring, not a production deployment claim. The PostgreSQL upload-session repository is source-validated separately and is not yet selected by `cmd/server`; a restart therefore does not preserve the development runtime's in-memory session metadata.

## Live application-consumer acceptance checkpoint

A controlled target-environment acceptance run on `goreecloud-vps-01` completed successfully for exact Drive revision `00b35aabbf529ba5605430993b571a23996e324e` against the deployed Wardveil Scan service at revision `52a1de08e3fe771acab6c308e7af36914242de07`.

That exact run proved:

- clean upload finalization published only the inspected bytes and the published bytes matched staging;
- EICAR was classified as malicious, blocked from publication, and retained in staging;
- the malicious decision generated a non-destructive Quarantine handoff that still requires explicit executor authority;
- an invalid Drive Scan credential failed closed;
- an unavailable Scan endpoint failed closed;
- the Drive consumer did not access ClamAV directly.

The live evidence remains exact-revision-bound to `00b35aabbf529ba5605430993b571a23996e324e`. Later descendants do not inherit target-environment acceptance automatically.

## Runtime negative acceptance command

`cmd/wardveil-negative-acceptance` expands the target-environment failure matrix while keeping the already-passed clean/EICAR runner separate.

The command distinguishes two evidence classes:

- **Live Wardveil transport cases:** an exact replay uses a fixed signed nonce/timestamp/correlation request and must return the cached equivalent envelope; a conflicting request reusing that nonce must be rejected with HTTP 409 by the deployed Wardveil Scan service.
- **Controlled Drive enforcement cases:** a private loopback timeout and controlled authoritative-envelope injection exercise Drive's real upload service, staging boundary, `StagedFileGate`, publication decision, and fail-closed behavior for timeout, expired evidence, digest mismatch, changed-during-scan content, suspicious results, unknown results, and unsupported results.

Controlled envelope injection is application-consumer evidence only. It does not claim the controlled producer is a deployed Wardveil service or that the deployed scanner naturally emitted those states. The command records replay durability, revoked-credential testing, stale-signature testing, and capacity exhaustion as unproven until exact target-environment evidence exists.

The command requires the exact source revision under test and the existing owner-only Scan secret file. Sanitized JSON output excludes the caller secret and raw test payloads.

## Result semantics

| Wardveil result | Drive behavior |
| --- | --- |
| `clean` | Allow the requested lifecycle action only when authoritative evidence is current, unexpired, digest-bound, scope-bound, and has evidence references. |
| `suspicious` | Hold for review; do not release. |
| `malicious` | Block and produce a Wardveil Quarantine handoff. An exact malicious digest remains blocking even if the original evidence validity window later expires. |
| `unknown` | Fail closed as unverified. |
| `unsupported` | Fail closed as unverified. |

The evaluator also defines the same security semantics for future `open`, `download`, `share`, and `restore_release` paths. Those routes are not claimed as implemented by this milestone.

## Quarantine authority

A blocked staged upload remaining outside the active object namespace is a Drive safety hold, not by itself canonical Wardveil Quarantine. A quarantine operation requires an explicitly authorized executor. Quarantine is not deletion and must preserve the applicable recovery, audit, policy, and evidence obligations.

## Privacy Shield boundary

Cross-service security identity uses stable internal Space/node IDs and a SHA-256 digest. Raw file contents are supplied to the authorized scanning operation when required but are not placed in shared security records. User-facing filenames, credentials, access tokens, and unrelated account metadata are not required in the Wardveil file identity or evidence contract.

## Everkeep restore boundary

Everkeep remains authoritative for backup, restore, preservation, and recovery verification. A future restored Drive object must satisfy applicable Everkeep restore verification first and then pass Wardveil file-security verification before Drive releases it into the active namespace. Wardveil scanning does not replace Everkeep restore verification, and Drive does not claim Everkeep authority.

## Production acceptance

Drive's upload-finalization application-consumer path is now runtime validated for the exact live checkpoint above, but `production_runtime_status` remains `unaccepted`.

Production acceptance still requires, at minimum:

- exact-revision execution of the expanded negative matrix in the target environment;
- stale-signature, revoked-credential, and capacity/concurrency evidence against the applicable deployed runtime;
- durable production upload-session persistence and single-writer or equivalent synchronization so staged bytes cannot change between final verification and publication;
- production GoreeCloud Identity/service-key lifecycle, rotation, revocation, and deployment-appropriate durable replay protection;
- download/open/share enforcement when those runtime capabilities are implemented;
- authorized Wardveil Quarantine execution with target-state readback and reconciliation evidence;
- Wardveil Audit/Security Center provenance acceptance;
- Everkeep restore-path acceptance before restored content is released;
- Privacy Shield runtime data-minimization validation;
- Glaze UI states for scanning, held, blocked, unavailable, and quarantine/recovery outcomes.

Green source CI, a successful controlled consumer case, or a prior exact-revision live run must not be generalized into a broader production or `Protected by Wardveil` claim.
