# Wardveil Scan Live Drive Acceptance

This runbook validates GoreeCloud Drive's own upload-finalization integration against a deployed Wardveil Scan transport.

The acceptance command is intentionally application-owned. It constructs Drive's real `uploads.Service`, `storage.Local`, `wardveil.StagedFileGate`, and signed `wardveil.HTTPScanner` instead of sending a standalone synthetic Wardveil request.

## What the command proves

Against the configured loopback Wardveil Scan service, the command verifies:

- clean staged content is scanned through Wardveil, rehashed by Drive, and atomically published only after a current authoritative clean decision;
- EICAR test content is blocked with `block_quarantine`, remains in staging, and is not published into the active object namespace;
- the malicious decision generates a non-destructive `QuarantineHandoff` that still requires explicit executor authority;
- an invalid caller secret fails closed as `ErrSecurityUnavailable` and does not publish content;
- an unavailable Wardveil Scan endpoint fails closed as `ErrSecurityUnavailable` and does not publish content;
- the Drive acceptance path never connects directly to ClamAV.

The command emits only sanitized structural evidence. It does not emit caller secrets or raw test payloads.

## Required credential boundary

Drive consumes its caller secret from a separate owner-only file containing exactly one credential value. The file must not be readable or writable by group or other users. Do not place the secret in command arguments, source control, shared evidence, changelogs, or ordinary logs.

The caller ID and key ID must match an active entry accepted by the deployed Wardveil Scan service. For the initial Drive deployment candidate these are `goreecloud-drive` and `scan-current` with `drive_file` scope.

## Example

```sh
go run ./cmd/wardveil-acceptance \
  --endpoint http://127.0.0.1:8791/v1/scan \
  --secret-file /etc/goreecloud/drive/wardveil-scan.secret \
  --caller-id goreecloud-drive \
  --key-id scan-current \
  --source-revision <exact-drive-revision> \
  --output /tmp/goreecloud-drive-wardveil-acceptance.json
```

Run it only from an exact reviewed Drive source revision in the target environment. Preserve the resulting sanitized JSON as acceptance evidence only after checking the exact source revision, service endpoint, and credential-file permissions.

## Acceptance boundary

A passing run can establish deployed Drive application-consumer execution through the current Development upload path. It does not independently establish production GoreeCloud Identity/key lifecycle, durable distributed replay protection, production PostgreSQL upload-session wiring, production object storage, authorized Quarantine execution/readback, Wardveil Audit persistence, Security Center acceptance, Privacy Shield runtime acceptance, Everkeep recovery acceptance, Stable qualification, or a broad `Protected by Wardveil` claim.

The command deliberately records `quarantine_execution: not_proven`, `production_service_identity: not_proven`, and `production_runtime_acceptance: unaccepted` until those independent gates are completed.
