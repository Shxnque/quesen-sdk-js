/**
 * TSC v2 (Typed Security Context) support — the Quesen "agent firewall".
 *
 * One call before any high-risk agent action returns a deterministic
 * PASS / REVIEW / BLOCK / SKIP decision plus an audit receipt. Maps 1:1 onto
 * the engine's `POST /tsc/validate` route (ADR-042), registered only when the
 * engine runs with `QUESEN_TSC_V2_ENABLED=true`.
 *
 * Zero interpretation: builders only assemble a JSON object; the SDK never
 * inspects or executes any string content. The engine is the sole authority.
 */

export const TSC_VERSION = "2.0";

export type TscDecisionKind = "PASS" | "REVIEW" | "BLOCK" | "SKIP";
export type TrustTier = "trusted" | "verified" | "unverified" | "unknown";
export type ProvenanceSource =
  | "client_asserted"
  | "adapter_derived"
  | "engine_derived"
  | "trusted_metadata";
export type Framework =
  | "langchain" | "crewai" | "autogen" | "ag2" | "mcp"
  | "openai_assistants" | "raw" | "other" | "unknown";
export type DataClass =
  | "public" | "internal" | "confidential" | "pii" | "financial"
  | "credential" | "secret" | "regulated" | "unknown";
export type CapabilityClass =
  | "read" | "write" | "network" | "exec" | "financial"
  | "admin" | "comms" | "filesystem" | "other";

/** A fully-formed Typed Security Context body (what the engine accepts). */
export interface TscContext {
  tsc_version: string;
  subject: Record<string, unknown>;
  action: Record<string, unknown>;
  provenance: Record<string, unknown>;
  target?: Record<string, unknown>;
  tool?: Record<string, unknown>;
  permissions?: Record<string, unknown>;
  data?: Record<string, unknown>;
  signals?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  client_request_id?: string;
}

export interface TscReason {
  code: string;
  severity: string;
  message: string;
}

/** Deterministic decision + audit receipt from POST /tsc/validate. */
export interface TscDecision {
  tsc_version: string;
  decision: TscDecisionKind;
  risk_score: number;
  confidence: number;
  reasons: TscReason[];
  tags: string[];
  policy: Record<string, unknown>;
  provenance_summary: Record<string, unknown>;
  engine_version: string;
  commit_sha: string;
  input_snapshot_hash: string;
  latency_ms: number;
  request_id: string;
  client_request_id?: string | null;
}

/** Thrown by requirePass() when the decision is not an explicit PASS. */
export class TscBlockedError extends Error {
  readonly decision: TscDecision;
  constructor(decision: TscDecision) {
    const codes = decision.reasons.map((r) => r.code).join(", ") || "no_reasons";
    super(
      `Quesen firewall ${decision.decision} (risk=${decision.risk_score}, ` +
        `reasons=[${codes}], request_id=${decision.request_id})`,
    );
    this.name = "TscBlockedError";
    this.decision = decision;
  }
}

/** True ONLY for an explicit PASS. Fail-closed by construction. */
export function isAllowed(d: TscDecision): boolean {
  return d.decision === "PASS";
}

export function reasonCodes(d: TscDecision): string[] {
  return d.reasons.map((r) => r.code);
}

/** Return the decision if PASS, else throw TscBlockedError. */
export function requirePass(d: TscDecision): TscDecision {
  if (!isAllowed(d)) throw new TscBlockedError(d);
  return d;
}

function clean(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null) out[k] = v;
  }
  return out;
}

// ---- scenario builders (the common catastrophic actions) ----

export interface DataEgressOpts {
  dataClasses: DataClass[] | string[];
  to: string;
  destinationTrust?: TrustTier;
  subjectKind?: string;
  framework?: Framework;
  provenance?: ProvenanceSource;
  clientRequestId?: string;
}

/** Agent is about to send data OUT to some destination. */
export function dataEgressContext(o: DataEgressOpts): TscContext {
  const trust = o.destinationTrust ?? "unverified";
  const ctx: TscContext = {
    tsc_version: TSC_VERSION,
    subject: clean({ kind: o.subjectKind ?? "agent", framework: o.framework }),
    action: { kind: "data_egress" },
    provenance: { source: o.provenance ?? "adapter_derived" },
    target: { kind: "endpoint", identifier: o.to, trust_tier: trust },
    data: {
      classes: [...o.dataClasses],
      egress: { to: o.to, destination_trust: trust },
    },
  };
  if (o.clientRequestId) ctx.client_request_id = o.clientRequestId;
  return ctx;
}

export interface ToolCallOpts {
  capabilityClass: CapabilityClass | string;
  grantedScopes?: string[];
  requestedScopes?: string[];
  policyRequired?: string[];
  subjectKind?: string;
  trustTier?: TrustTier;
  framework?: Framework;
  provenance?: ProvenanceSource;
  injectionSuspected?: boolean;
  injectionPatterns?: string[];
  clientRequestId?: string;
}

/** Agent is about to invoke a tool / capability. */
export function toolCallContext(o: ToolCallOpts): TscContext {
  const permissions = clean({
    granted: o.grantedScopes,
    requested: o.requestedScopes,
    policy_required: o.policyRequired,
  });
  const ctx: TscContext = {
    tsc_version: TSC_VERSION,
    subject: clean({
      kind: o.subjectKind ?? "agent",
      trust_tier: o.trustTier ?? "unknown",
      framework: o.framework,
    }),
    action: { kind: "tool_call" },
    provenance: { source: o.provenance ?? "adapter_derived" },
    tool: clean({
      capability_class: o.capabilityClass,
      granted_scopes: o.grantedScopes,
      requested_scopes: o.requestedScopes,
    }),
  };
  if (Object.keys(permissions).length) ctx.permissions = permissions;
  if (o.injectionSuspected !== undefined || o.injectionPatterns) {
    ctx.signals = {
      prompt_injection: clean({
        suspected: o.injectionSuspected,
        patterns: o.injectionPatterns,
      }),
    };
  }
  if (o.clientRequestId) ctx.client_request_id = o.clientRequestId;
  return ctx;
}

export interface PaymentOpts {
  grantedScopes?: string[];
  trustTier?: TrustTier;
  subjectKind?: string;
  framework?: Framework;
  provenance?: ProvenanceSource;
  clientRequestId?: string;
}

/** Agent is about to move money / perform a financial action. */
export function paymentContext(o: PaymentOpts = {}): TscContext {
  const ctx: TscContext = {
    tsc_version: TSC_VERSION,
    subject: clean({
      kind: o.subjectKind ?? "agent",
      trust_tier: o.trustTier ?? "unverified",
      framework: o.framework,
    }),
    action: { kind: "payment" },
    provenance: { source: o.provenance ?? "client_asserted" },
    tool: clean({ capability_class: "financial", granted_scopes: o.grantedScopes }),
    permissions: clean({ granted: o.grantedScopes }),
  };
  if (o.clientRequestId) ctx.client_request_id = o.clientRequestId;
  return ctx;
}
