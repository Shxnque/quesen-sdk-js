/**
 * Execution binding & evidence — mirror of the Python SDK `execution` module and the
 * engine `quesen.evidence` module (Quesen Upgrade P1a, Directive §6).
 *
 * A Quesen authorization decision must never be read as proof an action ran. This module
 * computes the canonical action hash and verifies an ExecutionEvidence is bound to the
 * exact action + authorization receipt (catching "approved X, executed Y").
 *
 * Determinism: Rule-A canonical JSON (recursive key-sort, compact, UTF-8, null-omitted)
 * matching the engine (quesen.asp.signing.canonical_json) and the Python SDK byte-for-byte.
 */
import { createHash } from "node:crypto";

const ACTION_FIELDS = ["subject", "action", "target", "parameters"] as const;

/** Rule-A canonical JSON: recursive key-sort, compact, UTF-8, null/undefined omitted. */
export function ruleACanonical(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return "[" + value.map(ruleACanonical).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== null && obj[k] !== undefined)
      .sort();
    const body = keys.map((k) => JSON.stringify(k) + ":" + ruleACanonical(obj[k])).join(",");
    return "{" + body + "}";
  }
  // string | number | boolean
  return JSON.stringify(value);
}

export function canonicalActionBytes(action: Record<string, unknown>): Buffer {
  const payload: Record<string, unknown> = {};
  for (const k of ACTION_FIELDS) {
    if (k in action && action[k] !== null && action[k] !== undefined) payload[k] = action[k];
  }
  return Buffer.from(ruleACanonical(payload), "utf-8");
}

export function actionHash(action: Record<string, unknown>): string {
  return "sha256:" + createHash("sha256").update(canonicalActionBytes(action)).digest("hex");
}

export interface BindingVerification {
  ok: boolean;
  bound: boolean;
  linked: boolean;
  reason: string;
}

type EvidenceLike = Record<string, unknown> & { toObject?: () => Record<string, unknown> };

export function verifyExecutionBinding(
  receipt: Record<string, unknown>,
  action: Record<string, unknown>,
  executionEvidence: EvidenceLike,
): BindingVerification {
  const ev = typeof executionEvidence.toObject === "function" ? executionEvidence.toObject() : executionEvidence;
  const expected = actionHash(action);
  const bound = ev["execution_binding"] === expected;
  const authSnap = receipt["input_snapshot_hash"] as string | undefined;
  const linked = authSnap ? ev["authorization_input_snapshot_hash"] === authSnap : false;

  if (!bound) {
    return { ok: false, bound: false, linked, reason: "execution_binding does not match the recomputed action hash — authorized action != executed action" };
  }
  if (authSnap && !linked) {
    return { ok: false, bound: true, linked: false, reason: "binding matches the action but evidence is not linked to this authorization (input_snapshot_hash mismatch)" };
  }
  return { ok: true, bound: true, linked, reason: "execution evidence is bound to this action and authorization" };
}
