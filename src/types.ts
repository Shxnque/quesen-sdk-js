/**
 * Typed response records for the Quesen HTTP API.
 *
 * Every field mirrors the FastAPI Pydantic models exactly. If the server ever
 * ships a new optional field, the SDK forwards it verbatim (index signature at
 * the tail of each interface where appropriate) rather than dropping it.
 *
 * v0.2.0 tracks engine v1.10.0 (ADR-041 receipt provenance):
 *   ValidateResult now carries `input_snapshot_hash` and `commit_sha`.
 */

export type Decision = "PROCEED" | "REVIEW" | "SKIP";
export type Outcome = "RUG" | "LOSS" | "OK" | "WIN" | "UNKNOWN";

export interface WeightsSnapshot {
  domain_age: number;
  engagement: number;
  scam_keywords: number;
}

export interface ThresholdsSnapshot {
  skip: number;
  review: number;
}

export interface SourceVerification {
  is_verified?: boolean | null;
  unknown_reason?: string | null;
  explorer?: string | null;
}

export interface ProxyInfo {
  is_proxy?: boolean | null;
  proxy_standard?: string | null;
  implementation_address?: string | null;
  admin_address?: string | null;
  unknown_reason?: string | null;
}

export interface OwnershipModel {
  owner_address?: string | null;
  renounced?: boolean | null;
  unknown_reason?: string | null;
}

export interface HolderConcentration {
  top1_share?: number | null;
  top5_share?: number | null;
  top10_share?: number | null;
  total_holders?: number | null;
  unknown_reason?: string | null;
}

export interface OnchainEnrichment {
  chain: string;
  chain_id: number;
  contract_address: string;
  has_code?: boolean | null;
  creation_block?: number | null;
  contract_age_days?: number | null;
  source_verification: SourceVerification;
  proxy: ProxyInfo;
  ownership: OwnershipModel;
  holder_concentration: HolderConcentration;
  probes_run: string[];
  probes_skipped: string[];
  errors: string[];
  status: "full" | "partial" | "disabled" | "no_config" | "invalid_input";
}

export interface ValidateInput {
  domain_age_days?: number;
  engagement_ratio?: number;
  scam_keyword_count?: number;
  client_request_id?: string;
  /** Optional EVM chain slug for on-chain enrichment (v1.5.0). */
  chain?: string;
  /** Optional 0x-prefixed EVM contract address for on-chain enrichment (v1.5.0). */
  contract_address?: string;
}

export interface ValidateResult {
  decision: Decision;
  risk_score: number;
  confidence: number;
  conflict_triggers: string[];
  latency_ms: number;
  request_id: string;
  engine_version: string;
  weights: WeightsSnapshot;
  thresholds: ThresholdsSnapshot;
  client_request_id?: string | null;
  key_owner?: string | null;
  onchain_enrichment?: OnchainEnrichment | null;
  /**
   * v1.10.0 (ADR-041) receipt provenance pair. Always present on live engines
   * running v1.10.0+. Marked optional here so callers hitting a pre-v1.10
   * engine keep type-checking cleanly.
   */
  input_snapshot_hash?: string;
  commit_sha?: string;
}

export interface SimulateInput extends ValidateInput {
  weights_override?: Partial<WeightsSnapshot>;
  thresholds_override?: Partial<ThresholdsSnapshot>;
}

export interface SimulateDelta {
  risk_score_delta: number;
  decision_changed: boolean;
}

export interface SimulateResult {
  baseline: ValidateResult;
  simulated: ValidateResult;
  delta: SimulateDelta;
}

export interface ReportInput {
  request_id: string;
  outcome: Outcome;
  notes?: string;
  realized_pnl?: number;
  elapsed_seconds?: number;
  venue?: string;
  signal_hash?: string;
  client_request_id?: string;
}

export interface ReportOutcomeCounters {
  total: number;
  by_outcome: Record<string, number>;
  pnl_reported_count: number;
  pnl_mean?: number | null;
}

export interface ReportResult {
  accepted: boolean;
  received_at: string;
  request_id: string;
  report_schema_version: string;
  engine_version: string;
  counters: ReportOutcomeCounters;
}
