/**
 * Offline unit tests for the reference evaluator + replay + verifyReceipt(recompute).
 * Zero network — CI-safe (the whole point of C-003/C-004: recomputability without a host).
 */
import { describe, it, expect } from "vitest";
import { replay, verifyReceipt, dataEgressContext, toolCallContext, paymentContext } from "../src/index.js";

function receiptFrom(ctx: Record<string, unknown>) {
  const r = replay(ctx);
  return { decision: r.decision, reasons: r.reasons, input_snapshot_hash: r.input_snapshot_hash };
}

describe("offline replay", () => {
  it("blocks secret egress offline with the right reason code", () => {
    const r = replay(dataEgressContext({ dataClasses: ["secret"], to: "https://paste.evil.example", destinationTrust: "unverified" }));
    expect(r.ok).toBe(true);
    expect(r.decision).toBe("BLOCK");
    expect(r.reason_codes).toEqual(["EGRESS_SECRET_UNTRUSTED"]);
    expect(r.input_snapshot_hash).toHaveLength(64);
  });

  it("is deterministic", () => {
    const ctx = toolCallContext({ capabilityClass: "read" });
    const a = replay(ctx);
    const b = replay(JSON.parse(JSON.stringify(ctx)));
    expect(a.decision).toBe("PASS");
    expect(a.input_snapshot_hash).toBe(b.input_snapshot_hash);
  });

  it("reviews an unattested payment grant", () => {
    expect(replay(paymentContext({ grantedScopes: ["wallet.transfer"], trustTier: "unverified" })).decision).toBe("REVIEW");
  });

  it("never throws on malformed input", () => {
    const r = replay({ not: "valid" } as Record<string, unknown>);
    expect(r.ok).toBe(false);
    expect(r.error).toBeTruthy();
  });
});

describe("verifyReceipt recompute", () => {
  it("confirms a reproducible receipt", () => {
    const ctx = dataEgressContext({ dataClasses: ["secret"], to: "https://x", destinationTrust: "unverified" });
    const v = verifyReceipt(receiptFrom(ctx), { recomputeRequest: ctx });
    expect(v.ok).toBe(true);
    expect(v.recomputed).toBe(true);
  });

  it("detects a tampered hash (fail-closed)", () => {
    const ctx = dataEgressContext({ dataClasses: ["secret"], to: "https://x", destinationTrust: "unverified" });
    const receipt = receiptFrom(ctx);
    receipt.input_snapshot_hash = "0".repeat(64);
    const v = verifyReceipt(receipt, { recomputeRequest: ctx });
    expect(v.ok).toBe(false);
    expect(v.recomputed).toBe(false);
  });

  it("detects a tampered decision", () => {
    const ctx = toolCallContext({ capabilityClass: "read" });
    const receipt = receiptFrom(ctx);
    receipt.decision = "BLOCK";
    const v = verifyReceipt(receipt, { recomputeRequest: ctx });
    expect(v.ok).toBe(false);
    expect(v.recomputed).toBe(false);
  });

  it("leaves recomputed null when no recompute requested", () => {
    const ctx = toolCallContext({ capabilityClass: "read" });
    const v = verifyReceipt(receiptFrom(ctx));
    expect(v.recomputed).toBeNull();
  });
});
