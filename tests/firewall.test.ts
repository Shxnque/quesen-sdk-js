import { describe, expect, it } from "vitest";

import { QuesenClient, QuesenFirewall } from "../src/index.js";
import { TscBlockedError, type TscDecision } from "../src/tsc.js";

const BLOCK: TscDecision = {
  tsc_version: "2.0",
  decision: "BLOCK",
  risk_score: 1.0,
  confidence: 0.3429,
  reasons: [{ code: "EGRESS_SECRET_UNTRUSTED", severity: "critical", message: "x" }],
  tags: ["exfiltration"],
  policy: {},
  provenance_summary: {},
  engine_version: "1.10.0",
  commit_sha: "a".repeat(40),
  input_snapshot_hash: "b".repeat(64),
  latency_ms: 0,
  request_id: "r1",
};
const PASS: TscDecision = {
  ...BLOCK,
  decision: "PASS",
  risk_score: 0.0,
  reasons: [{ code: "NO_ADVERSE_SIGNAL", severity: "info", message: "ok" }],
  tags: [],
  request_id: "r2",
};

const SANDBOX = {
  api_key: "sk_sandbox_deadbeef",
  tier: "sandbox",
  price_per_call: 0,
  rate_limit_per_min: 30,
  starter_credits: 1000,
  engine_version: "1.10.0",
};

/** Fetch mock that routes /sandbox/keys and /tsc/validate, capturing headers. */
function onboardingFetch() {
  const calls: Array<{ url: string; apiKey: string | null; body: string }> = [];
  const impl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    const headers = new Headers((init ?? {}).headers as HeadersInit);
    calls.push({ url, apiKey: headers.get("X-API-Key"), body: String((init ?? {}).body ?? "") });
    if (url.endsWith("/sandbox/keys")) {
      return new Response(JSON.stringify(SANDBOX), { status: 200, headers: { "content-type": "application/json" } });
    }
    const body = JSON.parse(String((init ?? {}).body ?? "{}"));
    const classes: string[] = body?.data?.classes ?? [];
    return new Response(JSON.stringify(classes.includes("secret") ? BLOCK : PASS), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch: impl, calls };
}

describe("QuesenClient.createSandboxKey", () => {
  it("mints a key and applies it to the client", async () => {
    const { fetch } = onboardingFetch();
    const c = new QuesenClient({ baseUrl: "https://engine", fetch });
    expect(c.apiKey).toBeUndefined();
    const resp = await c.createSandboxKey();
    expect(resp.api_key).toBe("sk_sandbox_deadbeef");
    expect(c.apiKey).toBe("sk_sandbox_deadbeef");
  });
});

describe("QuesenFirewall onboarding", () => {
  it("sandbox() mints a key then BLOCKs secret egress with the key attached", async () => {
    const { fetch, calls } = onboardingFetch();
    const fw = await QuesenFirewall.sandbox("https://engine", { fetch });
    await expect(
      fw.requirePass({ agent: "a", action: "send_data", target: "https://paste.evil", dataClass: "secret" }),
    ).rejects.toBeInstanceOf(TscBlockedError);
    // first call minted the key; the firewall call carried it
    const fwCall = calls.find((c) => c.url.endsWith("/tsc/validate"));
    expect(fwCall?.apiKey).toBe("sk_sandbox_deadbeef");
  });

  it("allows a safe read tool_call", async () => {
    const { fetch } = onboardingFetch();
    const fw = await QuesenFirewall.sandbox("https://engine", { fetch });
    expect(await fw.allows({ agent: "a", action: "tool_call", capabilityClass: "read" })).toBe(true);
  });
});
