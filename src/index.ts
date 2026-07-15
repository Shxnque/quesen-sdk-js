/**
 * Quesen JavaScript / TypeScript SDK — public surface.
 *
 * Deterministic-first design. This SDK is a THIN wrapper over the Quesen HTTP
 * API. It contains ZERO business logic. Every response is a plain, typed record.
 *
 * Design principles (published at https://github.com/Shxnque/quesen):
 *   §1  Priority: revenue > adoption > determinism.
 *   §2  No randomness, no ML, no prompts. This SDK never introduces any.
 *   §11 Ecosystem neutrality: no framework lock-in, zero runtime deps.
 *
 * Works on Node 18+, Bun, Deno, and modern browsers (fetch is required).
 */

export { QuesenClient } from "./client.js";
export type { QuesenClientOptions } from "./client.js";
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

export const VERSION = "0.1.0";
