import { WorkerEntrypoint } from "cloudflare:workers";

type Scope = {
  resource_type: string;
  resource_id: string;
};

type ApplyRequest = {
  operation_id: string;
  correlation_id: string;
  scope: Scope;
};

type ApplyResult = {
  status: "applied" | "already_applied" | "failed" | "unknown";
  operation_id: string;
  state_ref: string;
  evidence_ref: string;
  reason: string;
};

type ReadResult = {
  status: "quarantined" | "not_quarantined" | "unknown";
  operation_id?: string;
  state_ref?: string;
  evidence_ref?: string;
};

type Env = {
  DRIVE_QUARANTINE_ORIGIN: string;
  DRIVE_QUARANTINE_SERVICE_TOKEN: string;
};

function requireDriveScope(scope: Scope): void {
  if (!scope || scope.resource_type !== "drive_file") throw new Error("unsupported_resource_type");
  const match = /^drive:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):file:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(scope.resource_id);
  if (!match) throw new Error("invalid_drive_resource_id");
}

function requireOperationID(value: string, reason: string): void {
  if (typeof value !== "string" || value.length < 1 || value.length > 160 || !/^[A-Za-z0-9_.:-]+$/.test(value)) {
    throw new Error(reason);
  }
}

function origin(env: Env): URL {
  if (!env.DRIVE_QUARANTINE_SERVICE_TOKEN) throw new Error("drive_quarantine_service_token_unavailable");
  const parsed = new URL(env.DRIVE_QUARANTINE_ORIGIN);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("invalid_drive_quarantine_origin");
  }
  if (parsed.pathname !== "/" && parsed.pathname !== "") throw new Error("invalid_drive_quarantine_origin");
  parsed.pathname = "/";
  return parsed;
}

async function callDrive<T>(env: Env, path: string, body: unknown): Promise<T> {
  const url = new URL(path, origin(env));
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${env.DRIVE_QUARANTINE_SERVICE_TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  const text = await response.text();
  if (text.length > 32 * 1024) throw new Error("drive_quarantine_response_too_large");
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new Error("invalid_drive_quarantine_response");
  }
  if (!response.ok && response.status !== 409 && response.status !== 503) {
    throw new Error(`drive_quarantine_http_${response.status}`);
  }
  return decoded as T;
}

export default class DriveQuarantineTarget extends WorkerEntrypoint<Env> {
  async fetch(_request: Request): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }

  async applyQuarantine(request: ApplyRequest): Promise<ApplyResult> {
    requireDriveScope(request.scope);
    requireOperationID(request.operation_id, "invalid_operation_id");
    requireOperationID(request.correlation_id, "invalid_correlation_id");
    const result = await callDrive<ApplyResult>(this.env, "/internal/v1/wardveil/quarantine/apply", request);
    if (!result || !["applied", "already_applied", "failed", "unknown"].includes(result.status)) {
      throw new Error("invalid_drive_quarantine_response");
    }
    if (result.operation_id !== request.operation_id) throw new Error("drive_quarantine_operation_mismatch");
    if ((result.status === "applied" || result.status === "already_applied") && (!result.state_ref || !result.evidence_ref)) {
      throw new Error("drive_quarantine_readback_missing");
    }
    return result;
  }

  async readQuarantine(request: { scope: Scope }): Promise<ReadResult | null> {
    requireDriveScope(request.scope);
    const result = await callDrive<ReadResult>(this.env, "/internal/v1/wardveil/quarantine/read", request);
    if (!result || !["quarantined", "not_quarantined", "unknown"].includes(result.status)) {
      throw new Error("invalid_drive_quarantine_response");
    }
    if (result.status === "quarantined" && (!result.operation_id || !result.state_ref || !result.evidence_ref)) {
      throw new Error("drive_quarantine_readback_missing");
    }
    return result;
  }
}
