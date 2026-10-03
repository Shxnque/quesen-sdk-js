/**
 * Cross-language canonical-receipt-bytes parity (Quesen Upgrade P0.2) — JS SDK side.
 *
 * Self-contained: reads the vector fixture shipped WITH the SDK package
 * (`tests/fixtures/canonical_receipt_bytes.json`). The monorepo guards that this
 * fixture stays byte-identical to the canonical `conformance/vectors/` source
 * (`conformance/test_canonical_parity.py :: test_js_fixture_matches_canonical_vectors`),
 * so the published package carries its own conformance proof without reaching
 * outside its own tree (keeps sovereign↔public SDK byte-identity).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createHash } from "node:crypto";
import { canonicalReceiptBytes } from "../src/receipt.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.resolve(here, "fixtures/canonical_receipt_bytes.json");
const doc = JSON.parse(readFileSync(vectorsPath, "utf-8")) as {
  vectors: Array<{ name: string; receipt: Record<string, unknown>; canonical_bytes_utf8: string; sha256_canonical_bytes: string }>;
};

describe("canonical_receipt_bytes cross-language parity", () => {
  for (const vec of doc.vectors) {
    it(`matches vector: ${vec.name}`, () => {
      const out = canonicalReceiptBytes(vec.receipt);
      expect(out.toString("utf-8")).toBe(vec.canonical_bytes_utf8);
      expect(createHash("sha256").update(out).digest("hex")).toBe(vec.sha256_canonical_bytes);
    });
  }

  it("excludes non-signed fields (latency_ms/request_id/risk_score)", () => {
    const out = canonicalReceiptBytes({
      decision: "PASS",
      input_snapshot_hash: "a".repeat(64),
      commit_sha: "deadbeef",
      reasons: [{ code: "OK" }],
      latency_ms: 999,
      request_id: "should-not-appear",
      risk_score: 0.42,
    }).toString("utf-8");
    for (const forbidden of ["latency_ms", "request_id", "risk_score"]) {
      expect(out).not.toContain(forbidden);
    }
  });
});
