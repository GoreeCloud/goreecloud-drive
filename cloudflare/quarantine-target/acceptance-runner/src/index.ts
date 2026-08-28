type Scope = {
  resource_type: string;
  resource_id: string;
};

type ReadResult = {
  status: "quarantined" | "not_quarantined" | "unknown";
  operation_id?: string;
  state_ref?: string;
  evidence_ref?: string;
};

type Env = {
  DRIVE_QUARANTINE_TARGET: {
    readQuarantine(request: { scope: Scope }): Promise<ReadResult | null>;
  };
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return Response.json({ service: "goreecloud-drive-quarantine-target-acceptance-runner", mode: "local-only" });
    }
    if (request.method !== "POST" || url.pathname !== "/run") {
      return new Response("Not Found", { status: 404 });
    }

    const spaceID = crypto.randomUUID();
    const nodeID = crypto.randomUUID();
    const scope: Scope = {
      resource_type: "drive_file",
      resource_id: `drive:${spaceID}:file:${nodeID}`,
    };
    const result = await env.DRIVE_QUARANTINE_TARGET.readQuarantine({ scope });
    if (!result || result.status !== "not_quarantined") {
      return Response.json({ accepted: false, reason: "non_mutating_readback_failed", result }, { status: 503 });
    }
    return Response.json({
      accepted: true,
      reason: "internal_target_and_drive_readback_reachable",
      mutation_performed: false,
      scope,
      result,
    });
  },
} satisfies ExportedHandler<Env>;
