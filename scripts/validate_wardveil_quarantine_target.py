#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.drive-quarantine-target.json"
WORKER = ROOT / "cloudflare" / "quarantine-target" / "src" / "index.ts"
WRANGLER = ROOT / "cloudflare" / "quarantine-target" / "wrangler.jsonc"
RUNNER = ROOT / "cloudflare" / "quarantine-target" / "acceptance-runner" / "src" / "index.ts"
DEPLOY = ROOT / ".github" / "workflows" / "deploy-quarantine-target.yml"
STORAGE = ROOT / "internal" / "storage" / "quarantine.go"
HTTP = ROOT / "internal" / "httpapi" / "quarantine.go"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    contract = json.loads(CONTRACT.read_text())
    worker = WORKER.read_text()
    wrangler = json.loads(WRANGLER.read_text())
    runner = RUNNER.read_text()
    deploy = DEPLOY.read_text()
    storage = STORAGE.read_text()
    http = HTTP.read_text()

    require(contract["contract_version"] == "0.1.0", "unexpected quarantine target contract version")
    require(contract["owner"] == "GoreeCloud Drive", "Drive must remain resource authority")
    require(contract["resource_type"] == "drive_file", "unexpected quarantine resource type")
    require(contract["target_worker"] == "goreecloud-drive-quarantine-target", "unexpected target Worker")
    require(contract["target_worker_public_http_mutation_allowed"] is False, "public mutation must stay disabled")
    require(contract["workers_dev_enabled"] is False and contract["preview_urls_enabled"] is False, "public Worker routes must stay disabled")
    require(contract["storage"]["pending_state_precedes_side_effect"] is True, "pending state must precede mutation")
    require(contract["storage"]["exact_operation_replay_is_idempotent"] is True, "exact replay must be idempotent")
    require(contract["storage"]["conflicting_operation_fails_closed"] is True, "conflicting operations must fail closed")
    require(contract["storage"]["payload_state_disagreement_requires_reconciliation"] is True, "state disagreement must require reconciliation")
    require(contract["storage"]["quarantine_is_deletion"] is False, "quarantine must not be deletion")
    require(contract["privacy"]["user_facing_filename_required"] is False, "filenames must not be required")
    require(contract["privacy"]["raw_file_content_in_quarantine_state"] is False, "raw content must not enter shared state")
    require(contract["privacy"]["credentials_or_tokens_in_quarantine_state"] is False, "credentials must not enter state")
    require(contract["everkeep_recovery_authority_preserved"] is True, "Everkeep authority must remain preserved")
    require(contract["production_runtime_status"] == "unaccepted", "source candidate must remain unaccepted")
    require(contract["production_protection_claim_allowed"] is False, "source candidate cannot authorize protection claim")

    require('return new Response("Not Found", { status: 404 })' in worker, "target Worker public fetch must return 404")
    require('scope.resource_type !== "drive_file"' in worker, "target Worker must reject non-Drive scopes")
    require('DRIVE_QUARANTINE_SERVICE_TOKEN' in worker, "target Worker must use dedicated Drive service token")
    require('AbortSignal.timeout(5000)' in worker, "target Worker must bound backend requests")
    require('redirect: "error"' in worker, "target Worker must reject backend redirects")
    require(wrangler["workers_dev"] is False and wrangler["preview_urls"] is False, "wrangler public routes must remain disabled")
    require(wrangler["vars"]["DRIVE_QUARANTINE_ORIGIN"] == "https://replace-at-deployment.invalid", "source origin must remain deployment placeholder")

    require('mutation_performed: false' in runner, "acceptance runner must remain non-mutating")
    require('readQuarantine' in runner and 'applyQuarantine' not in runner, "acceptance runner must not invoke quarantine mutation")

    for token in [
        "workflow_dispatch:",
        "expected_sha:",
        "environment: drive-production",
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ACCOUNT_ID",
        "DRIVE_QUARANTINE_ORIGIN",
        "DRIVE_QUARANTINE_SERVICE_TOKEN",
        "Verify approved main revision",
        "Deploy Drive quarantine target Worker",
        "Provision Drive service token secret",
        "Verify non-mutating Drive readback through target Worker",
        'mutation_performed":false',
    ]:
        require(token in deploy, f"deployment workflow missing invariant: {token}")

    require('Status:        "pending"' in storage, "storage must record pending state before mutation")
    require('ErrQuarantineConflict' in storage, "storage must expose conflicting-operation failure")
    require('ErrQuarantineReconciliation' in storage, "storage must expose reconciliation-required state")
    require('os.Link(object, quarantine)' in storage and 'os.Remove(object)' in storage, "quarantine must preserve then remove active payload")

    require('subtle.ConstantTimeCompare' in http, "service token comparison must be constant-time")
    require('StatusNotFound' in http, "unauthorized internal route should remain concealed")
    require('StatusServiceUnavailable' in http, "missing service authorization must fail closed")

    print("Drive Wardveil quarantine target validation passed")


if __name__ == "__main__":
    main()
