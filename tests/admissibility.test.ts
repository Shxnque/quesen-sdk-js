import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  checkAdmissibility,
  canonicalGrantBytes,
  grantHash,
  admissibilityEvidence,
} from "../src/admissibility.js";
import { actionHash } from "../src/execution.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "admissibility.json"), "utf-8"),
);

describe("admissibility cross-language parity (ADR-052)", () => {
  for (const vec of VEC.vectors) {
    it(vec.name, () => {
      expect(canonicalGrantBytes(vec.grant).toString("utf-8")).toBe(
        vec.grant_canonical_bytes_utf8,
      );
      expect(grantHash(vec.grant)).toBe(vec.grant_hash);
      const r = checkAdmissibility(vec.grant, vec.action);
      expect(r.admissible).toBe(vec.expected.admissible);
      expect(r.violations).toEqual(vec.expected.violations);
      expect(r.action_hash).toBe(vec.expected.action_hash);
    });
  }
});

describe("admissibility semantics", () => {
  const GRANT_A = {
    allowed_actions: ["payment.execute"],
    allowed_targets: ["https://vendor-a.example/api"],
    allowed_currencies: ["USDC"],
    max_amount: "5000.00",
  };

  it("operator example: $8000 to vendor-b is inadmissible", () => {
    const r = checkAdmissibility(GRANT_A, {
      action: "payment.execute",
      target: "https://vendor-b.example/api",
      parameters: { amount: "8000", currency: "USDC" },
    });
    expect(r.admissible).toBe(false);
    expect(r.violations).toEqual(["AMOUNT_EXCEEDS_MAX", "TARGET_NOT_ALLOWED"]);
  });

  it("boundary equal is admissible", () => {
    const r = checkAdmissibility(GRANT_A, {
      action: "payment.execute",
      target: "https://vendor-a.example/api",
      parameters: { amount: "5000.00", currency: "USDC" },
    });
    expect(r.admissible).toBe(true);
  });

  it("fail-closed on missing constrained amount", () => {
    const r = checkAdmissibility(GRANT_A, {
      action: "payment.execute",
      target: "https://vendor-a.example/api",
      parameters: { currency: "USDC" },
    });
    expect(r.admissible).toBe(false);
    expect(r.violations).toContain("AMOUNT_REQUIRED");
  });

  it("evidence binds authority to action", () => {
    const receipt = { decision: "PASS", input_snapshot_hash: "a".repeat(64) };
    const action = {
      action: "payment.execute",
      target: "https://vendor-a.example/api",
      parameters: { amount: "10", currency: "USDC" },
    };
    const ev = admissibilityEvidence(receipt, GRANT_A, action);
    expect(ev.authorization_input_snapshot_hash).toBe("a".repeat(64));
    expect(ev.execution_binding).toBe(actionHash(action));
    expect(ev.admissible).toBe(true);
  });
});
