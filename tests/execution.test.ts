/**
 * Cross-language execution-binding parity (Quesen Upgrade P1a, Directive §6) — JS SDK side.
 * Self-contained: reads the vector fixture shipped with the package
 * (tests/fixtures/execution_binding.json). The monorepo guards byte-identity to
 * conformance/vectors/ (conformance/test_execution_parity.py).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalActionBytes, actionHash, verifyExecutionBinding } from "../src/execution.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const doc = JSON.parse(readFileSync(path.resolve(here, "fixtures/execution_binding.json"), "utf-8")) as {
  vectors: Array<{ name: string; action: Record<string, unknown>; canonical_action_bytes_utf8: string; action_hash: string }>;
  binding_example: {
    receipt: Record<string, unknown>;
    action: Record<string, unknown>;
    execution_evidence: Record<string, unknown>;
  };
};

describe("execution-binding cross-language parity", () => {
  for (const vec of doc.vectors) {
    it(`action_hash matches vector: ${vec.name}`, () => {
      expect(canonicalActionBytes(vec.action).toString("utf-8")).toBe(vec.canonical_action_bytes_utf8);
      expect(actionHash(vec.action)).toBe(vec.action_hash);
    });
  }

  it("verifies a correctly-bound execution evidence", () => {
    const { receipt, action, execution_evidence } = doc.binding_example;
    const v = verifyExecutionBinding(receipt, action, execution_evidence);
    expect(v.ok).toBe(true);
    expect(v.bound).toBe(true);
    expect(v.linked).toBe(true);
  });

  it("rejects when the executed action differs from the authorized action", () => {
    const { receipt, action, execution_evidence } = doc.binding_example;
    const tampered = { ...action, parameters: { ...(action.parameters as object), amount: "9999.00" } };
    const v = verifyExecutionBinding(receipt, tampered, execution_evidence);
    expect(v.ok).toBe(false);
    expect(v.bound).toBe(false);
  });
});
