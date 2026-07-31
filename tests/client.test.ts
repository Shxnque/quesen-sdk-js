import { describe, expect, it } from "vitest";

import {
  QuesenAuthError,
  QuesenClient,
  QuesenError,
  QuesenRateLimitError,
  QuesenServerError,
  QuesenValidationError,
} from "../src/index.js";

/** Deterministic fetch mock. Records calls, returns pre-programmed responses. */
function makeMockFetch(
  handler: (url: string, init: RequestInit) => { status: number; body: unknown; headers?: Record<string, string> },
) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    const req = init ?? {};
    calls.push({ url, init: req });
    const { status, body, headers } = handler(url, req);
    const bodyStr = typeof body === "string" ? body : JSON.stringify(body);
    return new Response(bodyStr, {
      status,
      headers: { "content-type": "application/json", ...(headers ?? {}) },
    });
  };
  return { fetch: impl, calls };
}

describe("QuesenClient constructor", () => {
  it("requires baseUrl", () => {
    // @ts-expect-error runtime test
    expect(() => new QuesenClient({})).toThrow(QuesenError);
  });

  it("trims trailing slash from baseUrl", () => {
    const { fetch } = makeMockFetch(() => ({ status: 200, body: {} }));
    const c = new QuesenClient({ baseUrl: "https://api.example/", fetch });
    expect(c.baseUrl).toBe("https://api.example");
  });
});

describe("QuesenClient.health", () => {
  it("returns parsed body", async () => {
    const { fetch, calls } = makeMockFetch(() => ({
      status: 200,
      body: { status: "ok", engine_version: "1.5.0" },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch });
    const h = await c.health();
    expect(h.status).toBe("ok");
    expect(h.engine_version).toBe("1.5.0");
    expect(calls[0].url).toBe("https://api.example/health");
  });
});

describe("QuesenClient.validate", () => {
  it("posts payload and sends X-API-Key when configured", async () => {
    const { fetch, calls } = makeMockFetch(() => ({
      status: 200,
      body: {
        decision: "SKIP",
        risk_score: 1.0,
        confidence: 1.0,
        conflict_triggers: ["R1: New domain (<=30d) + unusually high engagement (>=0.50)"],
        latency_ms: 3,
        request_id: "abc",
        engine_version: "1.5.0",
        weights: { domain_age: 0.4, engagement: 0.35, scam_keywords: 0.25 },
        thresholds: { skip: 0.65, review: 0.35 },
      },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", apiKey: "sk_test", fetch });
    const r = await c.validate({ domain_age_days: 1, engagement_ratio: 0.95, scam_keyword_count: 4 });
    expect(r.decision).toBe("SKIP");
    expect(r.risk_score).toBe(1.0);
    expect(calls[0].init.method).toBe("POST");
    expect((calls[0].init.headers as Record<string, string>)["X-API-Key"]).toBe("sk_test");
    expect(calls[0].init.body).toContain("scam_keyword_count");
  });

  it("propagates client_request_id via header", async () => {
    const { fetch, calls } = makeMockFetch(() => ({
      status: 200,
      body: {
        decision: "PROCEED",
        risk_score: 0.1,
        confidence: 1.0,
        conflict_triggers: [],
        latency_ms: 1,
        request_id: "abc",
        engine_version: "1.5.0",
        weights: { domain_age: 0.4, engagement: 0.35, scam_keywords: 0.25 },
        thresholds: { skip: 0.65, review: 0.35 },
      },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch });
    await c.validate({ domain_age_days: 800, client_request_id: "trace-1" });
    expect((calls[0].init.headers as Record<string, string>)["X-Request-ID"]).toBe("trace-1");
  });

  it("forwards on-chain enrichment fields when provided", async () => {
    const { fetch, calls } = makeMockFetch(() => ({
      status: 200,
      body: {
        decision: "SKIP",
        risk_score: 0.9,
        confidence: 1.0,
        conflict_triggers: ["R7: High holder concentration (top1>=60%) + unusually high engagement"],
        latency_ms: 12,
        request_id: "abc",
        engine_version: "1.5.0",
        weights: { domain_age: 0.4, engagement: 0.35, scam_keywords: 0.25 },
        thresholds: { skip: 0.65, review: 0.35 },
        onchain_enrichment: {
          chain: "base",
          chain_id: 8453,
          contract_address: "0xabc",
          source_verification: {},
          proxy: {},
          ownership: {},
          holder_concentration: { top1_share: 0.72 },
          probes_run: [],
          probes_skipped: [],
          errors: [],
          status: "partial",
        },
      },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch });
    const r = await c.validate({
      engagement_ratio: 0.9,
      chain: "base",
      contract_address: "0x4200000000000000000000000000000000000006",
    });
    expect(r.onchain_enrichment?.chain).toBe("base");
    expect(r.onchain_enrichment?.holder_concentration.top1_share).toBe(0.72);
    // Body should include chain + contract_address.
    expect(calls[0].init.body).toContain('"chain"');
    expect(calls[0].init.body).toContain('"contract_address"');
  });
});

describe("QuesenClient error mapping", () => {
  it("maps 401 to QuesenAuthError", async () => {
    const { fetch } = makeMockFetch(() => ({ status: 401, body: { detail: "no key" } }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch, retries: 0 });
    await expect(c.validate({ domain_age_days: 1 })).rejects.toBeInstanceOf(QuesenAuthError);
  });

  it("maps 422 to QuesenValidationError", async () => {
    const { fetch } = makeMockFetch(() => ({ status: 422, body: { detail: "bad input" } }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch, retries: 0 });
    await expect(c.validate({ engagement_ratio: 5 as unknown as number })).rejects.toBeInstanceOf(
      QuesenValidationError,
    );
  });

  it("maps 429 to QuesenRateLimitError", async () => {
    const { fetch } = makeMockFetch(() => ({ status: 429, body: { detail: "slow down" } }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch, retries: 0 });
    await expect(c.validate({ domain_age_days: 1 })).rejects.toBeInstanceOf(QuesenRateLimitError);
  });

  it("retries 5xx up to `retries` times then throws QuesenServerError", async () => {
    let calls = 0;
    const { fetch } = makeMockFetch(() => {
      calls += 1;
      return { status: 500, body: { detail: "boom" } };
    });
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch, retries: 2, retryBackoffMs: 1 });
    await expect(c.health()).rejects.toBeInstanceOf(QuesenServerError);
    expect(calls).toBe(3); // 1 initial + 2 retries
  });
});

describe("QuesenClient.report", () => {
  it("posts v1.1 extended fields", async () => {
    const { fetch, calls } = makeMockFetch(() => ({
      status: 200,
      body: {
        accepted: true,
        received_at: "2026-07-16T00:00:00Z",
        request_id: "abc",
        report_schema_version: "1.1.0",
        engine_version: "1.5.0",
        counters: { total: 1, by_outcome: { WIN: 1 }, pnl_reported_count: 1, pnl_mean: 12.5 },
      },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch });
    const r = await c.report({
      request_id: "abc",
      outcome: "WIN",
      realized_pnl: 12.5,
      elapsed_seconds: 3600,
      venue: "base:uniswap-v3",
    });
    expect(r.accepted).toBe(true);
    expect(r.counters.by_outcome.WIN).toBe(1);
    expect(calls[0].init.body).toContain("realized_pnl");
    expect(calls[0].init.body).toContain("base:uniswap-v3");
  });
});

describe("QuesenClient.validate v1.10 receipt provenance", () => {
  it("surfaces input_snapshot_hash and commit_sha as typed fields", async () => {
    const { fetch } = makeMockFetch(() => ({
      status: 200,
      body: {
        decision: "SKIP",
        risk_score: 0.98,
        confidence: 1.0,
        conflict_triggers: ["R1"],
        latency_ms: 3,
        request_id: "abc",
        engine_version: "1.10.0",
        weights: { domain_age: 0.4, engagement: 0.35, scam_keywords: 0.25 },
        thresholds: { skip: 0.65, review: 0.35 },
        input_snapshot_hash: "e".repeat(64),
        commit_sha: "0".repeat(40),
      },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch });
    const r = await c.validate({ domain_age_days: 1, engagement_ratio: 0.95, scam_keyword_count: 4 });
    expect(typeof r.input_snapshot_hash).toBe("string");
    expect(r.input_snapshot_hash).toHaveLength(64);
    expect(typeof r.commit_sha).toBe("string");
    expect(r.commit_sha).toHaveLength(40);
  });

  it("accepts responses from pre-v1.10 engines that omit provenance fields", async () => {
    const { fetch } = makeMockFetch(() => ({
      status: 200,
      body: {
        decision: "PROCEED",
        risk_score: 0.1,
        confidence: 1.0,
        conflict_triggers: [],
        latency_ms: 1,
        request_id: "abc",
        engine_version: "1.9.0",
        weights: { domain_age: 0.4, engagement: 0.35, scam_keywords: 0.25 },
        thresholds: { skip: 0.65, review: 0.35 },
      },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch });
    const r = await c.validate({ domain_age_days: 800 });
    expect(r.decision).toBe("PROCEED");
    expect(r.input_snapshot_hash).toBeUndefined();
    expect(r.commit_sha).toBeUndefined();
  });

  it("commit_sha sentinel 'unknown' is a valid engine response", async () => {
    const { fetch } = makeMockFetch(() => ({
      status: 200,
      body: {
        decision: "REVIEW",
        risk_score: 0.5,
        confidence: 1.0,
        conflict_triggers: [],
        latency_ms: 2,
        request_id: "abc",
        engine_version: "1.10.0",
        weights: { domain_age: 0.4, engagement: 0.35, scam_keywords: 0.25 },
        thresholds: { skip: 0.65, review: 0.35 },
        input_snapshot_hash: "f".repeat(64),
        commit_sha: "unknown",
      },
    }));
    const c = new QuesenClient({ baseUrl: "https://api.example", fetch });
    const r = await c.validate({ domain_age_days: 60 });
    expect(r.commit_sha).toBe("unknown");
  });
});
