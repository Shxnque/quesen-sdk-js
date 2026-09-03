import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { verifyReceipt, requireReceipt, canonicalReceiptBytes } from "../src/receipt.js";

describe("receipt verification", () => {
  it("accepts an unsigned but structurally-sound receipt", () => {
    const v = verifyReceipt({ decision: "PASS", input_snapshot_hash: "a".repeat(64), commit_sha: "b".repeat(40) });
    expect(v.ok).toBe(true);
    expect(v.signed).toBe(false);
    expect(v.signatureValid).toBeNull();
    requireReceipt(v);
  });

  it("rejects a receipt with no input_snapshot_hash", () => {
    const v = verifyReceipt({ decision: "PASS", commit_sha: "b".repeat(40) });
    expect(v.ok).toBe(false);
    expect(() => requireReceipt(v)).toThrow();
  });

  it("canonical bytes are deterministic and field-ordered", () => {
    const r = { reasons: ["X"], commit_sha: "c".repeat(40), input_snapshot_hash: "d".repeat(64), decision: "BLOCK" };
    const b = canonicalReceiptBytes(r).toString("utf-8");
    expect(b).toBe('{"decision":"BLOCK","input_snapshot_hash":"' + "d".repeat(64) + '","commit_sha":"' + "c".repeat(40) + '","reasons":["X"]}');
  });

  it("verifies a genuine Ed25519 signature and detects tampering", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pubRawHex = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
    const r: Record<string, unknown> = { decision: "PASS", input_snapshot_hash: "e".repeat(64), commit_sha: "f".repeat(40), reasons: [] };
    r.signature = edSign(null, canonicalReceiptBytes(r), privateKey).toString("hex");
    const v = verifyReceipt(r, { publicKeyHex: pubRawHex });
    expect(v.signed).toBe(true);
    expect(v.signatureValid).toBe(true);
    r.decision = "BLOCK";
    expect(verifyReceipt(r, { publicKeyHex: pubRawHex }).signatureValid).toBe(false);
  });
});
