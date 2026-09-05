/**
 * Quesen JavaScript / TypeScript SDK — public surface.
 *
 * Deterministic-first design. This SDK is a THIN wrapper over the Quesen HTTP
 * API. It contains ZERO business logic. Every response is a plain, typed record.
 *
 * v0.2.0 tracks engine v1.10.0 (ADR-041 receipt provenance): every
 * `ValidateResult` now surfaces `input_snapshot_hash` and `commit_sha`.
 *
 * Design principles (published at https://github.com/Shxnque/quesen):
 *   §1  Priority: revenue > adoption > determinism.
 *   §2  No randomness, no ML, no prompts. This SDK never introduces any.
 *   §11 Ecosystem neutrality: no framework lock-in, zero runtime deps.
 *
 * Works on Node 18+, Bun, Deno, and modern browsers (fetch is required).
 */

export { QuesenClient } from "./client.js";
export type { QuesenClientOptions, SandboxKeyResponse } from "./client.js";
export { QuesenFirewall } from "./firewall.js";
export type { FirewallCheckOpts } from "./firewall.js";
export {
  QuesenError,
  QuesenAuthError,
  QuesenRateLimitError,
  QuesenValidationError,
  QuesenServerError,
  QuesenTimeout,
  QuesenTransportError,
} from "./errors.js";
export type {
  ValidateInput,
  SimulateInput,
  ReportInput,
  ValidateResult,
  SimulateResult,
  SimulateDelta,
  ReportResult,
  ReportOutcomeCounters,
  WeightsSnapshot,
  ThresholdsSnapshot,
  OnchainEnrichment,
  SourceVerification,
  ProxyInfo,
  OwnershipModel,
  HolderConcentration,
  Decision,
  Outcome,
} from "./types.js";
export {
  TSC_VERSION,
  TscBlockedError,
  isAllowed,
  reasonCodes,
  requirePass,
  dataEgressContext,
  toolCallContext,
  paymentContext,
} from "./tsc.js";
export type {
  TscContext,
  TscDecision,
  TscDecisionKind,
  TscReason,
  TrustTier,
  ProvenanceSource,
  Framework,
  DataClass,
  CapabilityClass,
  DataEgressOpts,
  ToolCallOpts,
  PaymentOpts,
} from "./tsc.js";

export {
  verifyReceipt,
  requireReceipt,
  canonicalReceiptBytes,
} from "./receipt.js";
export type { ReceiptVerification } from "./receipt.js";

export { replay } from "./replay.js";
export {
  evaluate as referenceEvaluate,
  normalize as referenceNormalize,
  canonicalJson as referenceCanonicalJson,
  inputSnapshotHash as referenceInputSnapshotHash,
  TscReferenceError,
  REFERENCE_VERSION,
} from "./reference.js";
export type { ReferenceResult } from "./reference.js";

export const VERSION = "0.6.0";
