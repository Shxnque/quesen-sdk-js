/**
 * Offline verdict replay — recompute a Quesen decision locally, with zero network.
 *
 * The JS-ecosystem answer to BEA criticism-ledger C-003 / C-004 ("recomputability before
 * adoption"): recompute the TSC v2 egress/authority verdict on your own machine and
 * compare it to the receipt the engine returned, instead of trusting a hosted closed
 * ruleset.
 *
 *   import { replay, dataEgressContext } from "quesen-sdk";
 *   const local = replay(dataEgressContext({ dataClasses: ["secret"], to: "https://x" }));
 *   // { ok: true, decision: "BLOCK", reason_codes: ["EGRESS_SECRET_UNTRUSTED"], input_snapshot_hash: ... }
 *
 * Honest boundary: reproduces the *contract-level* decision/reasons/hash for the
 * egress/authority subset, NOT the production risk weighting/thresholds.
 */
import { evaluate } from "./reference.js";
import type { ReferenceResult } from "./reference.js";
import type { TscContext } from "./tsc.js";

/** Locally recompute the deterministic verdict for a TSC v2 context — offline. */
export function replay(context: TscContext | Record<string, unknown>): ReferenceResult {
  return evaluate(context);
}
