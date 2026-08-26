import { describe, expect, it } from "vitest";

import { QuesenClient } from "../src/index.js";
import {
  TscBlockedError,
  dataEgressContext,
  toolCallContext,
  paymentContext,
  isAllowed,
  reasonCodes,
  requirePass,
  type TscDecision,
} from "../src/tsc.js";

const BLOCK: TscDecision = {
  tsc_version: "2.0",
  decision: "BLOCK",
  risk_score: 1.0,
  confidence: 0.3429,
  reasons: [
    { code: "EGRESS_SECRET_UNTRUSTED", severity: "critical", message: "credential/secret egress to an unverified destination" },
  ],
  tags: ["exfiltration"],
  policy: {},
  provenance_summary: { source: "adapter_derived", attested: false },
  engine_version: "1.10.0",
  commit_sha: "6d20f8d8f663acfd2747bbc742f6bb1745c2ac3d",
  input_snapshot_hash: "f".repeat(64),
  latency_ms: 0,
  request_id: "abc123",
};
const PASS: TscDecision = {
  ...BLOCK,
  decision: "PASS",
  risk_score: 0.0,
  reasons: [{ code: "NO_ADVERSE_SIGNAL", severity: "info", message: "no adverse signal" }],
  tags: [],
  request_id: "def456",
};

function mockFetch(response: unknown) {
  const calls: Array<{ url: string; body: string }> = [];
  const impl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    calls.push({ url, body: String((init ?? {}).body ?? "") });
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch: impl, calls };
}

describe("TSC context builders", () => {
  it("dataEgressContext assembles required sections", () => {
    const ctx = dataEgressContext({ dataClasses: ["secret"], to: "https://paste.x" });
    expect(ctx.tsc_version).toBe("2.0");
    expect(ctx.subject.kind).toBe("agent");
    expect(ctx.action.kind).toBe("data_egress");
    expect(ctx.provenance.source).toBe("adapter_derived");
    expect((ctx.data as any).classes).toEqual(["secret"]);
    expect((ctx.data as any).egress.to).toBe("https://paste.x");
  });

  it("toolCallContext carries injection signal", () => {
    const ctx = toolCallContext({ capabilityClass: "network", injectionSuspected: true });
    expect((ctx.tool as any).capability_class).toBe("network");
    expect((ctx.signals as any).prompt_injection.suspected).toBe(true);
  });

  it("paymentContext defaults to financial capability", () => {
    const ctx = paymentContext({ grantedScopes: ["payment.send"] });
    expect(ctx.action.kind).toBe("payment");
    expect((ctx.tool as any).capability_class).toBe("financial");
  });
});

describe("QuesenClient.validateTsc", () => {
  it("posts to /tsc/validate and returns a BLOCK decision", async () => {
    const { fetch, calls } = mockFetch(BLOCK);
    const c = new QuesenClient({ baseUrl: "https://engine", fetch });
    const d = await c.validateTsc(dataEgressContext({ dataClasses: ["secret"], to: "https://paste.evil" }));
    expect(calls[0].url).toBe("https://engine/tsc/validate");
    expect(calls[0].body).toContain("data_egress");
    expect(d.decision).toBe("BLOCK");
    expect(reasonCodes(d)).toContain("EGRESS_SECRET_UNTRUSTED");
    expect(isAllowed(d)).toBe(false);
  });

  it("requirePass throws TscBlockedError on BLOCK and returns on PASS", async () => {
    const blocked = new QuesenClient({ baseUrl: "https://engine", fetch: mockFetch(BLOCK).fetch });
    const dBlock = await blocked.validateTsc(dataEgressContext({ dataClasses: ["secret"], to: "x" }));
    expect(() => requirePass(dBlock)).toThrow(TscBlockedError);

    const ok = new QuesenClient({ baseUrl: "https://engine", fetch: mockFetch(PASS).fetch });
    const dPass = await ok.validateTsc(dataEgressContext({ dataClasses: ["public"], to: "x" }));
    expect(requirePass(dPass)).toBe(dPass);
    expect(isAllowed(dPass)).toBe(true);
  });
});
