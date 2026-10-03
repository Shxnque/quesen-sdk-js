/**
 * Admissibility — constraint-bound authority (ADR-052, Directive §9/§6). Mirror of the Python
 * SDK `admissibility` module and the engine `quesen.evidence.admissibility` module.
 *
 * A Quesen authorization grants a BOUNDED authority (a set of constraints). This module decides
 * whether a SPECIFIC proposed action is admissible within that grant — e.g. a grant for
 * `payment.execute <= 5000.00 USDC to vendor-a` makes an `8000 USDC to vendor-b` action
 * INADMISSIBLE. An authorization receipt alone never implies the action was within scope.
 *
 * Determinism: Rule-A canonical JSON + no-float decimal comparison, identical to the engine and
 * the Python SDK so admissibility results agree cross-language byte-for-byte.
 */
import { createHash } from "node:crypto";
import { actionHash, ruleACanonical } from "./execution.js";

export const GRANT_FIELDS = [
  "allowed_actions",
  "allowed_targets",
  "allowed_currencies",
  "max_amount",
  "max_qty",
] as const;

const DECIMAL_RE = /^\d+(\.\d+)?$/;

export function canonicalGrantBytes(grant: Record<string, unknown>): Buffer {
  const payload: Record<string, unknown> = {};
  for (const k of Object.keys(grant)) {
    if (grant[k] !== null && grant[k] !== undefined) payload[k] = grant[k];
  }
  return Buffer.from(ruleACanonical(payload), "utf-8");
}

export function grantHash(grant: Record<string, unknown>): string {
  return "sha256:" + createHash("sha256").update(canonicalGrantBytes(grant)).digest("hex");
}

function toDecimalStr(v: unknown): string | null {
  if (typeof v === "boolean") return null;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) {
      const s = String(v);
      return DECIMAL_RE.test(s) ? s : null;
    }
    return String(v);
  }
  if (typeof v === "string" && DECIMAL_RE.test(v)) return v;
  return null;
}

function normDecimal(s: string): [string, string] {
  let i: string;
  let f: string;
  const dot = s.indexOf(".");
  if (dot >= 0) {
    i = s.slice(0, dot);
    f = s.slice(dot + 1);
  } else {
    i = s;
    f = "";
  }
  i = i.replace(/^0+/, "") || "0";
  f = f.replace(/0+$/, "");
  return [i, f];
}

function cmpDecimal(a: string, b: string): number {
  const [ai, af0] = normDecimal(a);
  const [bi, bf0] = normDecimal(b);
  if (ai.length !== bi.length) return ai.length < bi.length ? -1 : 1;
  if (ai !== bi) return ai < bi ? -1 : 1;
  const width = Math.max(af0.length, bf0.length);
  const af = af0.padEnd(width, "0");
  const bf = bf0.padEnd(width, "0");
  if (af === bf) return 0;
  return af < bf ? -1 : 1;
}

export interface AdmissibilityResult {
  admissible: boolean;
  violations: string[];
  grant_hash: string;
  action_hash: string;
}

export function checkAdmissibility(
  grant: Record<string, unknown>,
  action: Record<string, unknown>,
): AdmissibilityResult {
  const params = (action["parameters"] as Record<string, unknown>) || {};
  const act = action["action"];
  const tgt = action["target"];
  const amount = params["amount"];
  const currency = params["currency"];
  const qty = params["qty"];

  const v: string[] = [];

  const allowedActions = grant["allowed_actions"] as unknown[] | undefined | null;
  if (allowedActions !== null && allowedActions !== undefined) {
    if (!allowedActions.includes(act)) v.push("ACTION_NOT_ALLOWED");
  }
  const allowedTargets = grant["allowed_targets"] as unknown[] | undefined | null;
  if (allowedTargets !== null && allowedTargets !== undefined) {
    if (!allowedTargets.includes(tgt)) v.push("TARGET_NOT_ALLOWED");
  }
  const allowedCurrencies = grant["allowed_currencies"] as unknown[] | undefined | null;
  if (allowedCurrencies !== null && allowedCurrencies !== undefined) {
    if (currency === null || currency === undefined) v.push("CURRENCY_REQUIRED");
    else if (!allowedCurrencies.includes(currency)) v.push("CURRENCY_NOT_ALLOWED");
  }
  const maxAmount = grant["max_amount"];
  if (maxAmount !== null && maxAmount !== undefined) {
    if (amount === null || amount === undefined) {
      v.push("AMOUNT_REQUIRED");
    } else {
      const a = toDecimalStr(amount);
      const cap = toDecimalStr(maxAmount);
      if (a === null || cap === null) v.push("AMOUNT_MALFORMED");
      else if (cmpDecimal(a, cap) > 0) v.push("AMOUNT_EXCEEDS_MAX");
    }
  }
  const maxQty = grant["max_qty"];
  if (maxQty !== null && maxQty !== undefined) {
    if (qty === null || qty === undefined) {
      v.push("QTY_REQUIRED");
    } else if (typeof qty !== "number" || !Number.isInteger(qty)) {
      v.push("QTY_MALFORMED");
    } else if (qty > (maxQty as number)) {
      v.push("QTY_EXCEEDS_MAX");
    }
  }

  const violations = Array.from(new Set(v)).sort();
  return {
    admissible: violations.length === 0,
    violations,
    grant_hash: grantHash(grant),
    action_hash: actionHash(action),
  };
}

export function admissibilityEvidence(
  receipt: Record<string, unknown>,
  grant: Record<string, unknown>,
  action: Record<string, unknown>,
): Record<string, unknown> {
  const r = checkAdmissibility(grant, action);
  return {
    authorization_input_snapshot_hash: receipt["input_snapshot_hash"] ?? null,
    authorization_decision: receipt["decision"] ?? null,
    grant_hash: r.grant_hash,
    execution_binding: r.action_hash,
    admissible: r.admissible,
    violations: r.violations,
  };
}
