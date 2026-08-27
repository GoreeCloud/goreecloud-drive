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

This repository currently proves source behavior and CI-tested security invariants only. `production_runtime_status` remains `unaccepted`.

Production acceptance still requires, at minimum:

- deployed authenticated Drive-to-Wardveil transport;
- deployed healthy scanner runtime and current signature-health evidence behind Wardveil;
- target-environment clean, EICAR/malicious, suspicious, unsupported, timeout, unavailable, digest-mismatch, stale-evidence, and concurrent-finalization tests;
- durable single-writer or equivalent synchronization so staged bytes cannot change between final verification and publication;
- download/open/share enforcement when those runtime capabilities are implemented;
- authorized Wardveil Quarantine execution and recovery evidence;
- Everkeep restore-path acceptance before restored content is released;
- Privacy Shield data-minimization validation;
- Glaze UI states for scanning, held, blocked, unavailable, and quarantine/recovery outcomes.

Green source CI is not evidence that a deployed Drive instance is protected from malware.
