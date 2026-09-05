/**
 * Offline reference evaluator — the client-side answer to "recomputability before adoption".
 *
 * Byte-for-byte TypeScript port of the Python SDK's `quesen_sdk/reference.py`, which is in
 * turn a vendored copy of the PUBLIC reference evaluator
 * `Shxnque/quesen : evaluation/tsc_v2_poc.py` (which the sovereign engine
 * `quesen/tsc/decide.py` declares it mirrors). It lets any JS/TS consumer recompute the
 * TSC v2 egress/authority `{decision, reason_codes, input_snapshot_hash}` **entirely
 * offline, zero network, zero dependency** (Node's built-in crypto only) and assert it
 * matches a receipt the hosted engine returned.
 *
 * Why (BEA criticism-ledger C-003 / C-004): a receipt proving *input integrity* is not the
 * same as being able to *reproduce the decision*. This closes that gap in the JS ecosystem.
 *
 * Canonicalization matches Python exactly: recursive key sort, compact separators, literal
 * (non-escaped) UTF-8, sha256 — so hashes agree byte-for-byte across both SDKs and the engine.
 *
 * Honest boundary: reproduces the *contract-level* decision/reasons/hash for the
 * egress/authority subset — NOT the production risk weighting/thresholds.
 */
import { createHash } from "node:crypto";

export const REFERENCE_VERSION = "tsc-v2-ref-1";

export class TscReferenceError extends Error {
  readonly code: string;
  readonly pointer: string;
  constructor(code: string, message: string, pointer = "") {
    super(message);
    this.name = "TscReferenceError";
    this.code = code;
    this.pointer = pointer;
  }
  asObject(): { code: string; message: string; pointer: string } {
    return { code: this.code, message: this.message, pointer: this.pointer };
  }
}

type Dict = Record<string, any>;

const ENUMS: Record<string, Set<string>> = {
  "subject.kind": new Set(["agent", "human", "service", "unknown"]),
  "subject.framework": new Set([
    "langchain", "crewai", "autogen", "ag2", "mcp",
    "openai_assistants", "raw", "other", "unknown",
  ]),
  trust_tier: new Set(["trusted", "verified", "unverified", "unknown"]),
  "action.kind": new Set([
    "tool_call", "http_request", "data_read", "data_write",
    "data_egress", "message_post", "payment", "code_exec",
    "file_access", "other",
  ]),
  "target.kind": new Set([
    "endpoint", "domain", "contract", "account", "file",
    "dataset", "recipient", "tool", "service", "other", "unknown",
  ]),
  "tool.capability_class": new Set([
    "read", "write", "network", "exec", "financial",
    "admin", "comms", "filesystem", "other",
  ]),
  "data.class": new Set([
    "public", "internal", "confidential", "pii", "financial",
    "credential", "secret", "regulated", "unknown",
  ]),
  "provenance.source": new Set([
    "client_asserted", "adapter_derived", "engine_derived", "trusted_metadata",
  ]),
  "attestation.method": new Set(["none", "signed", "oauth_introspection", "mtls"]),
};

const TOP_LEVEL_KEYS = new Set([
  "tsc_version", "policy", "subject", "action", "target", "tool",
  "permissions", "data", "signals", "provenance", "client_request_id",
]);

const SENSITIVE_ACTIONS = new Set(["payment", "code_exec", "data_egress", "data_write", "file_access"]);
const SENSITIVE_CAPABILITIES = new Set(["financial", "admin", "exec", "write", "filesystem"]);
const MAX_INTENT_LEN = 2000;

// ---- normalization helpers ----

const nfc = (s: string): string => s.normalize("NFC");

function normEnum(value: any, name: string, pointer: string): string {
  if (typeof value !== "string") throw new TscReferenceError("invalid_type", `${name} must be a string`, pointer);
  const v = nfc(value).trim().toLowerCase();
  if (!ENUMS[name].has(v)) {
    throw new TscReferenceError("invalid_enum", `${name}=${JSON.stringify(value)} not in ${JSON.stringify([...ENUMS[name]].sort())}`, pointer);
  }
  return v;
}

function normStr(value: any, pointer: string, maxLen: number): string {
  if (typeof value !== "string") throw new TscReferenceError("invalid_type", `expected string at ${pointer}`, pointer);
  const v = nfc(value).trim();
  if (v.length > maxLen) throw new TscReferenceError("oversized", `string at ${pointer} exceeds ${maxLen} chars`, pointer);
  return v;
}

function normDomain(value: any, pointer: string): string {
  return normStr(value, pointer, 253).toLowerCase().replace(/\.+$/, "");
}

function normStrList(value: any, pointer: string, name?: string): string[] {
  if (!Array.isArray(value)) throw new TscReferenceError("invalid_type", `expected list at ${pointer}`, pointer);
  const out = new Set<string>();
  value.forEach((item, i) => {
    if (name) out.add(normEnum(item, name, `${pointer}[${i}]`));
    else out.add(normStr(item, `${pointer}[${i}]`, 128).toLowerCase());
  });
  return [...out].sort();
}

function normInt(value: any, pointer: string, minimum?: number): number {
  if (typeof value === "boolean" || !Number.isInteger(value)) {
    throw new TscReferenceError("invalid_type", `expected integer at ${pointer}`, pointer);
  }
  if (minimum !== undefined && value < minimum) {
    throw new TscReferenceError("out_of_range", `${pointer} must be >= ${minimum}`, pointer);
  }
  return value;
}

function normFloat(value: any, pointer: string, lo: number, hi: number): number {
  if (typeof value === "boolean" || typeof value !== "number") {
    throw new TscReferenceError("invalid_type", `expected number at ${pointer}`, pointer);
  }
  if (!(lo <= value && value <= hi)) {
    throw new TscReferenceError("out_of_range", `${pointer} must be in [${lo},${hi}]`, pointer);
  }
  return value;
}

function obj(value: any, pointer: string, allowed: Set<string>): Dict {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TscReferenceError("invalid_type", `expected object at ${pointer}`, pointer);
  }
  const unknown = Object.keys(value).filter((k) => !allowed.has(k));
  if (unknown.length) {
    throw new TscReferenceError("unknown_field", `unknown field(s) ${JSON.stringify(unknown.sort())} at ${pointer}`, pointer);
  }
  return value;
}

export function normalize(ctx: any): Dict {
  if (ctx === null || typeof ctx !== "object" || Array.isArray(ctx)) {
    throw new TscReferenceError("malformed", "context must be a JSON object", "/");
  }
  obj(ctx, "/", TOP_LEVEL_KEYS);

  let tv = ctx.tsc_version;
  if (tv === undefined || tv === null) throw new TscReferenceError("unsupported_version", "tsc_version required for v2 pipeline", "/tsc_version");
  tv = normStr(tv, "/tsc_version", 16);
  if (!tv.startsWith("2.")) throw new TscReferenceError("unsupported_version", `unsupported tsc_version ${JSON.stringify(tv)}`, "/tsc_version");

  const out: Dict = { tsc_version: tv };

  if (!("subject" in ctx)) throw new TscReferenceError("missing_required", "subject is required", "/subject");
  const s = obj(ctx.subject, "/subject", new Set(["id", "kind", "framework", "trust_tier"]));
  const subj: Dict = { kind: normEnum(s.kind ?? "unknown", "subject.kind", "/subject/kind") };
  if ("id" in s) subj.id = normStr(s.id, "/subject/id", 256);
  if ("framework" in s) subj.framework = normEnum(s.framework, "subject.framework", "/subject/framework");
  subj.trust_tier = normEnum(s.trust_tier ?? "unknown", "trust_tier", "/subject/trust_tier");
  out.subject = subj;

  if (!("action" in ctx)) throw new TscReferenceError("missing_required", "action is required", "/action");
  const a = obj(ctx.action, "/action", new Set(["kind", "operation", "intent"]));
  const act: Dict = { kind: normEnum(a.kind ?? "other", "action.kind", "/action/kind") };
  if ("operation" in a) act.operation = normStr(a.operation, "/action/operation", 128);
  if ("intent" in a) act.intent = normStr(a.intent, "/action/intent", MAX_INTENT_LEN);
  out.action = act;

  if (!("provenance" in ctx)) throw new TscReferenceError("missing_required", "provenance is required", "/provenance");
  const p = obj(ctx.provenance, "/provenance", new Set(["source", "as_of", "attestation", "evidence_refs"]));
  const prov: Dict = { source: normEnum(p.source ?? "client_asserted", "provenance.source", "/provenance/source") };
  if ("as_of" in p) prov.as_of = normStr(p.as_of, "/provenance/as_of", 40);
  if ("attestation" in p) {
    const at = obj(p.attestation, "/provenance/attestation", new Set(["method", "verified"]));
    const att: Dict = { method: normEnum(at.method ?? "none", "attestation.method", "/provenance/attestation/method") };
    const ver = at.verified ?? false;
    if (typeof ver !== "boolean") throw new TscReferenceError("invalid_type", "attestation.verified must be boolean", "/provenance/attestation/verified");
    att.verified = ver;
    prov.attestation = att;
  }
  if ("evidence_refs" in p) prov.evidence_refs = normStrList(p.evidence_refs, "/provenance/evidence_refs");
  out.provenance = prov;

  if ("policy" in ctx) {
    const pol = obj(ctx.policy, "/policy", new Set(["id", "version"]));
    const o: Dict = {};
    if ("id" in pol) o.id = normStr(pol.id, "/policy/id", 128);
    if ("version" in pol) o.version = normStr(pol.version, "/policy/version", 32);
    out.policy = o;
  }

  if ("target" in ctx) {
    const t = obj(ctx.target, "/target", new Set(["kind", "identifier", "domain", "trust_tier"]));
    const o: Dict = {};
    if ("kind" in t) o.kind = normEnum(t.kind, "target.kind", "/target/kind");
    if ("identifier" in t) o.identifier = normStr(t.identifier, "/target/identifier", 512);
    if ("domain" in t) o.domain = normDomain(t.domain, "/target/domain");
    o.trust_tier = normEnum(t.trust_tier ?? "unknown", "trust_tier", "/target/trust_tier");
    out.target = o;
  }

  if ("tool" in ctx) {
    const tl = obj(ctx.tool, "/tool", new Set(["id", "capability_class", "requested_scopes", "granted_scopes"]));
    const o: Dict = {};
    if ("id" in tl) o.id = normStr(tl.id, "/tool/id", 256);
    if ("capability_class" in tl) o.capability_class = normEnum(tl.capability_class, "tool.capability_class", "/tool/capability_class");
    if ("requested_scopes" in tl) o.requested_scopes = normStrList(tl.requested_scopes, "/tool/requested_scopes");
    if ("granted_scopes" in tl) o.granted_scopes = normStrList(tl.granted_scopes, "/tool/granted_scopes");
    out.tool = o;
  }

  if ("permissions" in ctx) {
    const pm = obj(ctx.permissions, "/permissions", new Set(["requested", "granted", "policy_required"]));
    const o: Dict = {};
    for (const fld of ["requested", "granted", "policy_required"]) {
      if (fld in pm) o[fld] = normStrList(pm[fld], `/permissions/${fld}`);
    }
    out.permissions = o;
  }

  if ("data" in ctx) {
    const d = obj(ctx.data, "/data", new Set(["classes", "egress"]));
    const o: Dict = {};
    if ("classes" in d) o.classes = normStrList(d.classes, "/data/classes", "data.class");
    if ("egress" in d) {
      const eg = obj(d.egress, "/data/egress", new Set(["to", "destination_trust"]));
      const e: Dict = {};
      if ("to" in eg) e.to = normStr(eg.to, "/data/egress/to", 512);
      e.destination_trust = normEnum(eg.destination_trust ?? "unknown", "trust_tier", "/data/egress/destination_trust");
      o.egress = e;
    }
    out.data = o;
  }

  if ("signals" in ctx) {
    const sg = obj(ctx.signals, "/signals", new Set(["prompt_injection", "domain_age_days", "engagement_ratio", "scam_keyword_count", "onchain"]));
    const o: Dict = {};
    if ("prompt_injection" in sg) {
      const pi = obj(sg.prompt_injection, "/signals/prompt_injection", new Set(["suspected", "patterns", "sample_ref"]));
      const po: Dict = {};
      if ("suspected" in pi) {
        if (typeof pi.suspected !== "boolean") throw new TscReferenceError("invalid_type", "prompt_injection.suspected must be boolean", "/signals/prompt_injection/suspected");
        po.suspected = pi.suspected;
      }
      if ("patterns" in pi) po.patterns = normStrList(pi.patterns, "/signals/prompt_injection/patterns");
      if ("sample_ref" in pi) po.sample_ref = normStr(pi.sample_ref, "/signals/prompt_injection/sample_ref", 128);
      o.prompt_injection = po;
    }
    if ("domain_age_days" in sg) o.domain_age_days = normInt(sg.domain_age_days, "/signals/domain_age_days", 0);
    if ("engagement_ratio" in sg) o.engagement_ratio = normFloat(sg.engagement_ratio, "/signals/engagement_ratio", 0.0, 1.0);
    if ("scam_keyword_count" in sg) o.scam_keyword_count = normInt(sg.scam_keyword_count, "/signals/scam_keyword_count", 0);
    if ("onchain" in sg) {
      if (sg.onchain === null || typeof sg.onchain !== "object" || Array.isArray(sg.onchain)) {
        throw new TscReferenceError("invalid_type", "signals.onchain must be an object", "/signals/onchain");
      }
      o.onchain = sg.onchain;
    }
    out.signals = o;
  }

  if ("client_request_id" in ctx) out.client_request_id = normStr(ctx.client_request_id, "/client_request_id", 128);

  return out;
}

// ---- canonicalization + hashing (matches Python json.dumps(sort_keys, separators=(",",":"), ensure_ascii=False)) ----

function sortDeep(v: any): any {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v !== null && typeof v === "object") {
    const out: Dict = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}

export function canonicalJson(obj: Dict, forHash = false): string {
  let material = obj;
  if (forHash) {
    const { client_request_id, ...rest } = obj;
    material = rest;
  }
  return JSON.stringify(sortDeep(material));
}

export function inputSnapshotHash(normalized: Dict): string {
  return createHash("sha256").update(Buffer.from(canonicalJson(normalized, true), "utf-8")).digest("hex");
}

// ---- reference decision function ----

function confidence(n: Dict): number {
  const present = ["subject", "action", "target", "tool", "permissions", "data", "signals"]
    .filter((k) => n[k] && (typeof n[k] !== "object" || Object.keys(n[k]).length || Array.isArray(n[k]))).length;
  return Math.round((present / 7.0) * 10000) / 10000;
}

function verdict(decision: string, risk: number, conf: number, reasons: Dict[], tags: string[], n: Dict): Dict {
  return {
    tsc_version: n.tsc_version,
    decision,
    risk_score: Math.round(risk * 10000) / 10000,
    confidence: conf,
    reasons,
    reason_codes: reasons.map((r) => r.code),
    tags: [...new Set(tags)].sort(),
    policy: n.policy ?? {},
    provenance_summary: {
      source: n.provenance.source,
      attested: Boolean(n.provenance.attestation?.verified) ||
        ["engine_derived", "trusted_metadata"].includes(n.provenance.source),
    },
    input_snapshot_hash: inputSnapshotHash(n),
    engine_version: REFERENCE_VERSION,
  };
}

export function decide(n: Dict): Dict {
  const reasons: Dict[] = [];
  const tags: string[] = [];

  const actionKind: string = n.action.kind;
  const prov = n.provenance;
  const attested = Boolean(prov.attestation?.verified) || ["engine_derived", "trusted_metadata"].includes(prov.source);

  const data = n.data ?? {};
  const classes = new Set<string>(data.classes ?? []);
  const egress = data.egress ?? {};
  const destTrust: string = egress.destination_trust ?? "unknown";

  const cap: string | undefined = n.tool?.capability_class;
  const sensitive = SENSITIVE_ACTIONS.has(actionKind) || (cap !== undefined && SENSITIVE_CAPABILITIES.has(cap));

  const granted = new Set<string>([...(n.permissions?.granted ?? []), ...(n.tool?.granted_scopes ?? [])]);
  const required = new Set<string>(n.permissions?.policy_required ?? []);

  const leaking = (classes.has("credential") || classes.has("secret")) &&
    ["data_egress", "message_post", "http_request"].includes(actionKind);
  if (leaking && ["unverified", "unknown"].includes(destTrust)) {
    reasons.push({ code: "EGRESS_SECRET_UNTRUSTED", severity: "critical", message: "credential/secret egress to an unverified destination" });
    return verdict("BLOCK", 1.0, confidence(n), reasons, [...tags, "exfiltration"], n);
  }

  if (required.size) {
    const effectiveGranted = attested ? granted : new Set<string>();
    const missing = [...required].filter((r) => !effectiveGranted.has(r)).sort();
    if (missing.length) {
      reasons.push({ code: "PRIVILEGE_MISMATCH", severity: "high", message: `missing/unverified required scope(s): ${JSON.stringify(missing)}` });
      return verdict(sensitive ? "BLOCK" : "REVIEW", sensitive ? 0.85 : 0.5, confidence(n), reasons, [...tags, "authz"], n);
    }
  }

  if (sensitive && granted.size && !attested) {
    reasons.push({ code: "UNVERIFIED_GRANT", severity: "medium", message: "authorization claimed by unattested client; cannot be trusted to PASS a sensitive action" });
    return verdict("REVIEW", 0.5, confidence(n), reasons, [...tags, "authz", "provenance"], n);
  }

  const pi = n.signals?.prompt_injection ?? {};
  if (pi.suspected) {
    const sev = sensitive ? "high" : "medium";
    reasons.push({ code: "PROMPT_INJECTION_SUSPECTED", severity: sev, message: `injection findings: ${JSON.stringify(pi.patterns ?? [])}` });
    return verdict("REVIEW", 0.6, confidence(n), reasons, [...tags, "prompt_injection"], n);
  }

  if ((classes.has("pii") || classes.has("financial") || classes.has("regulated")) &&
      ["data_egress", "http_request", "message_post"].includes(actionKind) &&
      ["unverified", "unknown"].includes(destTrust)) {
    reasons.push({ code: "PII_EGRESS_REVIEW", severity: "medium", message: "sensitive data class egress to a non-trusted destination" });
    return verdict("REVIEW", 0.55, confidence(n), reasons, [...tags, "data_egress"], n);
  }

  if (actionKind === "other" && !n.target && !n.tool && !n.data && !n.signals) {
    reasons.push({ code: "INSUFFICIENT_CONTEXT", severity: "info", message: "no target/tool/data/signals to reason over; engine declines to rule" });
    return verdict("SKIP", 0.0, confidence(n), reasons, tags, n);
  }

  reasons.push({ code: "NO_ADVERSE_SIGNAL", severity: "info", message: "no policy-relevant risk pattern matched" });
  return verdict("PASS", 0.1, confidence(n), reasons, tags, n);
}

export interface ReferenceResult {
  ok: boolean;
  decision?: string;
  reasons?: Dict[];
  reason_codes?: string[];
  input_snapshot_hash?: string;
  risk_score?: number;
  confidence?: number;
  tags?: string[];
  error?: { code: string; message: string; pointer: string };
}

/** Returns {ok, ...result} or {ok:false, error}. Never throws on malformed input. */
export function evaluate(ctx: any): ReferenceResult {
  let n: Dict;
  try {
    n = normalize(ctx);
  } catch (e) {
    if (e instanceof TscReferenceError) return { ok: false, error: e.asObject() };
    throw e;
  }
  return { ok: true, ...decide(n) };
}
