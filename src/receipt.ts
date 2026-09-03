/**
 * Receipt verification — mirror of the Python SDK's `receipt` module.
 *
 * Gives callers independent, client-side assurance over a Quesen decision
 * receipt: structural integrity (a pinnable `input_snapshot_hash`) and, when the
 * engine signs, an Ed25519 signature over the canonical receipt bytes. Uses
 * Node's built-in `crypto` (no extra dependency). Forward-compatible: unsigned
 * receipts verify at the structural level and report `signed: false`.
 *
 * Determinism: the canonical byte encoding matches the Python SDK exactly —
 * fixed field order, compact JSON, UTF-8 — so both sides agree byte-for-byte.
 */
import { verify as edVerify, createPublicKey } from "node:crypto";

/** Fixed field order the engine signs over (must match quesen-sdk-py). */
const SIGNED_FIELDS = ["decision", "input_snapshot_hash", "commit_sha", "reasons"] as const;

export interface ReceiptVerification {
  ok: boolean; // structural integrity (pinnable receipt)
  signed: boolean; // a signature was present
  signatureValid: boolean | null; // null if no signature / no key supplied
  reason: string;
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

/** Ed25519 raw (32-byte) public key -> a Node KeyObject via an SPKI DER wrapper. */
function ed25519PublicKeyFromHex(hex: string) {
  const raw = Buffer.from(hex, "hex");
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex"); // Ed25519 SPKI header
  return createPublicKey({ key: Buffer.concat([spkiPrefix, raw]), format: "der", type: "spki" });
}

/**
 * Independently verify a Quesen decision receipt on the caller's side.
 * `receipt` may be a TscDecision, a raw response object, or anything exposing
 * `.toObject()` / `.raw`.
 */
export function verifyReceipt(
  receipt: ReceiptLike,
  opts: { publicKeyHex?: string } = {},
): ReceiptVerification {
  const d = asObject(receipt);
  const decision = d["decision"];
  const snap = (d["input_snapshot_hash"] as string) || "";
  const sig = d["signature"] as string | undefined;

  if (!decision) return { ok: false, signed: Boolean(sig), signatureValid: null, reason: "no decision field on receipt" };
  if (!snap)
    return { ok: false, signed: Boolean(sig), signatureValid: null, reason: "receipt carries no input_snapshot_hash — not independently pinnable" };
  if (!sig)
    return { ok: true, signed: false, signatureValid: null, reason: "structurally sound; unsigned (engine signing not enabled / not provided)" };
  if (!opts.publicKeyHex)
    return { ok: true, signed: true, signatureValid: null, reason: "signature present but no publicKeyHex supplied to verify it" };

  try {
    const pub = ed25519PublicKeyFromHex(opts.publicKeyHex);
    const valid = edVerify(null, canonicalReceiptBytes(d), pub, Buffer.from(sig, "hex"));
    return valid
      ? { ok: true, signed: true, signatureValid: true, reason: "signature valid (Ed25519)" }
      : { ok: true, signed: true, signatureValid: false, reason: "signature INVALID — receipt not authentic" };
  } catch (e) {
    return { ok: true, signed: true, signatureValid: false, reason: `signature check error: ${(e as Error).message}` };
  }
}

/** Fail-closed: throw unless structurally sound AND (if signed) cryptographically valid. */
export function requireReceipt(v: ReceiptVerification): ReceiptVerification {
  if (!v.ok || (v.signed && v.signatureValid !== true)) {
    throw new Error(`receipt verification failed: ${v.reason}`);
  }
  return v;
}
