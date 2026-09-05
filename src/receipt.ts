/**
 * Receipt verification — mirror of the Python SDK's `receipt` module.
 *
 * Three, increasingly strong, levels of assurance — all running on the caller's machine:
 *   1. Structural integrity  — a verdict + a pinnable `input_snapshot_hash`.
 *   2. Cryptographic authenticity (optional) — Ed25519 over the canonical receipt bytes,
 *      via Node's built-in crypto (no extra dependency).
 *   3. Verdict reproducibility (optional) — with `recomputeRequest`, the decision +
 *      reason codes + `input_snapshot_hash` are recomputed OFFLINE from the public
 *      reference evaluator and compared to the receipt (BEA C-003 / C-004). A mismatch
 *      flips `ok` to false.
 *
 * Determinism: the canonical byte encoding matches the Python SDK exactly — fixed field
 * order, compact JSON, UTF-8 — so both sides agree byte-for-byte.
 */
import { verify as edVerify, createPublicKey } from "node:crypto";
import { evaluate } from "./reference.js";

/** Fixed field order the engine signs over (must match quesen-sdk-py). */
const SIGNED_FIELDS = ["decision", "input_snapshot_hash", "commit_sha", "reasons"] as const;

export interface ReceiptVerification {
  ok: boolean; // structural integrity (pinnable receipt)
  signed: boolean; // a signature was present
  signatureValid: boolean | null; // null if no signature / no key supplied
  reason: string;
  recomputed: boolean | null; // null if no recompute requested; else offline-replay match
}

type ReceiptLike = Record<string, unknown> & {
  toObject?: () => Record<string, unknown>;
  raw?: Record<string, unknown>;
};

function asObject(receipt: ReceiptLike): Record<string, unknown> {
  if (receipt && typeof receipt.toObject === "function") return receipt.toObject();
  if (receipt && receipt.raw && typeof receipt.raw === "object") return receipt.raw as Record<string, unknown>;
  return receipt as Record<string, unknown>;
}

/** Deterministic byte encoding the engine signs and the client re-derives. */
export function canonicalReceiptBytes(receipt: ReceiptLike): Buffer {
  const d = asObject(receipt);
  const ordered: Record<string, unknown> = {};
  for (const k of SIGNED_FIELDS) if (k in d) ordered[k] = d[k];
  return Buffer.from(JSON.stringify(ordered), "utf-8");
}

function ed25519PublicKeyFromHex(hex: string) {
  const raw = Buffer.from(hex, "hex");
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([spkiPrefix, raw]), format: "der", type: "spki" });
}

function verifyIntegrity(receipt: ReceiptLike, opts: { publicKeyHex?: string }): ReceiptVerification {
  const d = asObject(receipt);
  const decision = d["decision"];
  const snap = (d["input_snapshot_hash"] as string) || "";
  const sig = d["signature"] as string | undefined;

  if (!decision) return { ok: false, signed: Boolean(sig), signatureValid: null, recomputed: null, reason: "no decision field on receipt" };
  if (!snap)
    return { ok: false, signed: Boolean(sig), signatureValid: null, recomputed: null, reason: "receipt carries no input_snapshot_hash — not independently pinnable" };
  if (!sig)
    return { ok: true, signed: false, signatureValid: null, recomputed: null, reason: "structurally sound; unsigned (engine signing not enabled / not provided)" };
  if (!opts.publicKeyHex)
    return { ok: true, signed: true, signatureValid: null, recomputed: null, reason: "signature present but no publicKeyHex supplied to verify it" };

  try {
    const pub = ed25519PublicKeyFromHex(opts.publicKeyHex);
    const valid = edVerify(null, canonicalReceiptBytes(d), pub, Buffer.from(sig, "hex"));
    return valid
      ? { ok: true, signed: true, signatureValid: true, recomputed: null, reason: "signature valid (Ed25519)" }
      : { ok: true, signed: true, signatureValid: false, recomputed: null, reason: "signature INVALID — receipt not authentic" };
  } catch (e) {
    return { ok: true, signed: true, signatureValid: false, recomputed: null, reason: `signature check error: ${(e as Error).message}` };
  }
}

/**
 * Independently verify a Quesen decision receipt on the caller's side. `receipt` may be a
 * TscDecision, a raw response object, or anything exposing `.toObject()` / `.raw`.
 *
 * Pass `recomputeRequest` (the original TSC context) to additionally RECOMPUTE the verdict
 * offline from the public reference and assert it matches the receipt.
 */
export function verifyReceipt(
  receipt: ReceiptLike,
  opts: { publicKeyHex?: string; recomputeRequest?: Record<string, unknown> } = {},
): ReceiptVerification {
  const result = verifyIntegrity(receipt, opts);
  if (!opts.recomputeRequest) return result;

  const d = asObject(receipt);
  const ref = evaluate(opts.recomputeRequest);
  if (!ref.ok) {
    return { ...result, ok: false, recomputed: false, reason: result.reason + `; recompute FAILED — reference rejected input (${ref.error?.code})` };
  }
  const receiptReasonCodes = Array.isArray(d["reasons"])
    ? (d["reasons"] as Array<Record<string, unknown>>).map((r) => r["code"])
    : [];
  const matches =
    ref.decision === d["decision"] &&
    JSON.stringify(ref.reason_codes) === JSON.stringify(receiptReasonCodes) &&
    ref.input_snapshot_hash === d["input_snapshot_hash"];
  if (matches) {
    return { ...result, recomputed: true, reason: result.reason + "; verdict independently recomputed offline (decision + reasons + input_snapshot_hash match)" };
  }
  return {
    ...result,
    ok: false,
    recomputed: false,
    reason: result.reason + `; recompute MISMATCH — receipt not reproducible from public reference (local decision=${ref.decision}, hash_match=${ref.input_snapshot_hash === d["input_snapshot_hash"]})`,
  };
}

/** Fail-closed: throw unless structurally sound AND (if signed) valid AND (if recomputed) matching. */
export function requireReceipt(v: ReceiptVerification): ReceiptVerification {
  if (!v.ok || (v.signed && v.signatureValid !== true)) {
    throw new Error(`receipt verification failed: ${v.reason}`);
  }
  return v;
}
