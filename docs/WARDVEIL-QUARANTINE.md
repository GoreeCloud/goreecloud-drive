# Wardveil quarantine target

GoreeCloud Drive owns the authoritative quarantine state for `drive_file` resources. Wardveil may authorize and coordinate a quarantine action, but it does not become the owner of Drive file state merely because a Wardveil policy decision or executor exists.

## Resource identity

The target accepts only the canonical internal scope:

`drive:<space_id>:file:<node_id>`

User-facing filenames, source URLs, access tokens, and raw file contents are not part of the cross-service quarantine identity.

## Drive storage behavior

The local storage target adds two private namespaces alongside the existing active, staging, and trash boundaries:

- `quarantine` stores the isolated payload outside the active object namespace.
- `quarantine-state` stores minimized operation state and nonsecret provenance.

The operation sequence is deliberately recovery-safe:

1. Validate the exact Drive resource scope and bounded operation/correlation identifiers.
2. Create durable `pending` operation state before changing active content.
3. Hard-link the active payload into the private quarantine namespace.
4. Remove the active object only after the quarantine payload exists.
5. Atomically finalize the operation state as `quarantined`.
6. Require exact state/payload agreement on readback.

An exact replay of the same operation is idempotent. A different operation for an already claimed node fails closed. A payload/state disagreement becomes reconciliation-required rather than being reported as a successful or absent quarantine state.

Quarantine is not deletion. The payload remains recoverable under the applicable Drive, Wardveil, Privacy Shield, and Everkeep rules. Release or destructive removal requires a separate explicitly authorized workflow.

## Internal Drive service boundary

Drive exposes only two application-owned internal endpoints for the Cloudflare bridge:

- `POST /internal/v1/wardveil/quarantine/apply`
- `POST /internal/v1/wardveil/quarantine/read`

Both require the dedicated `GC_DRIVE_WARDVEIL_SERVICE_TOKEN`. When that token is not configured, the endpoints fail closed as unavailable. Missing or incorrect caller authorization is concealed as not found. The token is compared in constant time and must be supplied only through the deployment secret store.

These internal endpoints are not general user APIs and do not replace Drive account authorization, Wardveil runtime authorization, or the resource owner's final authority.

## Cloudflare target bridge

`cloudflare/quarantine-target/` contains the Drive-owned Worker RPC bridge named `goreecloud-drive-quarantine-target`.

The bridge:

- exposes no public mutation route; its public fetch handler returns `404`;
- has Workers.dev and preview URLs disabled;
- accepts only `drive_file` scope in canonical Drive resource-ID format;
- forwards minimized apply/read requests to the configured HTTPS Drive origin;
- uses the encrypted `DRIVE_QUARANTINE_SERVICE_TOKEN` Worker secret;
- rejects redirects and bounds backend requests to five seconds;
- validates successful apply/readback provenance before returning it to Wardveil.

The bridge is transport only. The Drive backend and storage layer remain authoritative for whether the file is actually isolated.

## Deployment gate

`.github/workflows/deploy-quarantine-target.yml` is manual and exact-revision bound. A production dispatch requires:

- the exact approved `main` SHA;
- Cloudflare deployment credentials in the `drive-production` environment;
- an HTTPS `DRIVE_QUARANTINE_ORIGIN` without embedded credentials, query, fragment, or application path;
- the Drive service token secret.

The workflow generates an ephemeral production Wrangler config, deploys the target Worker, provisions the encrypted service token, and then starts a local-only acceptance runner with a remote service binding. The runner performs only a randomized `readQuarantine` request for a nonexistent Drive resource and must receive `not_quarantined`. It never calls `applyQuarantine` and records `mutation_performed=false`.

This non-mutating probe proves internal Worker reachability and authenticated Drive readback only. It does not prove that an authorized production quarantine mutation has succeeded.

## Privacy Shield and Everkeep

Privacy Shield remains the privacy/data-minimization authority. Quarantine operation records use only stable internal identifiers, operation/correlation IDs, state references, evidence references, and timestamps. Raw content, user-facing filenames, credentials, and tokens are excluded.

Everkeep remains the resilience, backup, preservation, restore, and recovery-verification authority. Quarantine does not delete recovery material, and a later release or restore requires applicable Everkeep evidence independently of Wardveil security evidence.

## Production acceptance

`production_runtime_status` remains `unaccepted`.

Source implementation, CI, target deployment, or a non-mutating readback cannot independently authorize a `Protected by Wardveil` claim. Production acceptance still requires at minimum:

- an actually deployed Drive backend reachable only through the approved security boundary;
- a controlled authorized Wardveil quarantine mutation for a disposable Drive object;
- exact target-side payload/state readback after that mutation;
- executor and target replay/idempotency tests;
- timeout, crash, conflicting-operation, ambiguous-outcome, and reconciliation exercises;
- production Wardveil service identity, approved cryptography/key management, and least-privilege bindings;
- Security Center and Audit evidence for the exact runtime revision;
- quarantine release/recovery evidence;
- Privacy Shield acceptance;
- applicable Everkeep recovery acceptance.

Until those checks exist for the exact deployed revision, this repository proves a production-capable target path, not production quarantine enforcement.
