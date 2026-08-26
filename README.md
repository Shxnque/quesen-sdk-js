# quesen-sdk (JavaScript / TypeScript)

Official Quesen SDK for Node 18+, Bun, Deno, and modern browsers. Zero runtime
dependencies. Same 3-line integration pattern as every other Quesen SDK:

```ts
import { QuesenClient } from "quesen-sdk";

const q = new QuesenClient({
  baseUrl: "https://quesen.example.com",
  apiKey: process.env.QUESEN_API_KEY,
});

const verdict = await q.validate({
  domain_age_days: 1,
  engagement_ratio: 0.95,
  scam_keyword_count: 4,
});

if (verdict.decision === "SKIP") return; // respect the deterministic answer
```

> **Why deterministic?** No LLM, no randomness. Same input in, same decision out.
> Every response embeds `engine_version`, `weights`, `thresholds`, plus (v1.10+)
> `input_snapshot_hash` and `commit_sha` for self-contained replay.

---

**Status:** v0.4.0 · tracks Quesen engine v1.10.0 (+ TSC v2 agent firewall) · backward compatible with every deployed engine version.

---

## Install

```bash
npm i quesen-sdk           # or: yarn add quesen-sdk / bun add quesen-sdk
```

---

## 30-second agent firewall (copy-paste, no signup)

`QuesenFirewall.sandbox()` self-serves a **free** sandbox key (no signup, no card),
so this runs as-is against the hosted engine:

```ts
import { QuesenFirewall, TscBlockedError } from "quesen-sdk";

const fw = await QuesenFirewall.sandbox("https://web-production-aa5ba.up.railway.app");

try {
  await fw.requirePass({
    agent: "my-agent",
    action: "send_data",
    target: "https://paste.evil.example",
    dataClass: "secret",
  });
  await sendTheData();                    // only runs on an explicit PASS
} catch (e) {
  if (e instanceof TscBlockedError) {
    console.log(e.decision.decision);                   // 'BLOCK'
    console.log(e.decision.reasons.map((r) => r.code)); // ['EGRESS_SECRET_UNTRUSTED']
    console.log(e.decision.commit_sha);                 // audit-receipt ruleset pin
  }
}

// A safe action returns PASS:
const ok = await fw.check({ agent: "my-agent", action: "tool_call", capabilityClass: "read" });
console.log(ok.decision);                 // 'PASS'
```

> The hosted engine **requires** a key (no open mode). `QuesenFirewall.sandbox()`
> and `QuesenClient.createSandboxKey()` both call `POST /sandbox/keys` for a free,
> rate-limited key. For production volume pass `apiKey: "sk_live_..."`.

---

## Feature surface

- **`QuesenFirewall.sandbox(baseUrl)`** — zero-config agent firewall (mints a free key).
- **`.createSandboxKey()`** — self-serve a free sandbox key; auto-applied to the client.
- **`.health()`** — liveness probe.
- **`.version()`** — engine + report_schema versions + weights + thresholds + feature flags.
- **`.validate(input)`** — the main decision endpoint. Response carries `input_snapshot_hash` + `commit_sha` against v1.10+ engines.
- **`.simulate(input)`** — counterfactual scoring with `weights_override` / `thresholds_override`.
- **`.report(input)`** — post-decision outcome feedback (v1.1 schema with `realized_pnl`, `venue`, etc.).

### Agent Firewall (TSC v2) — lower-level

TSC v2 turns Quesen into a deterministic **agent firewall**: describe what your
autonomous agent is *about to do* and get a `PASS` / `REVIEW` / `BLOCK` / `SKIP`
verdict plus a tamper-evident audit receipt — *before* the action crosses a trust
boundary.

> Requires an engine running with `QUESEN_TSC_V2_ENABLED=true` (`POST /tsc/validate`).

```ts
import { QuesenClient, dataEgressContext, requirePass, TscBlockedError } from "quesen-sdk";

const q = new QuesenClient({ baseUrl: "https://web-production-aa5ba.up.railway.app" });
await q.createSandboxKey();               // free key (or pass apiKey: "sk_live_...")

// Agent is about to POST data somewhere — ask Quesen first.
const decision = await q.validateTsc(
  dataEgressContext({
    dataClasses: ["secret"],            // what's leaving
    to: "https://paste.evil.example",   // where it's going
    destinationTrust: "unverified",
    framework: "langchain",
  }),
);

console.log(decision.decision);                  // 'BLOCK'
console.log(decision.reasons.map((r) => r.code)); // ['EGRESS_SECRET_UNTRUSTED']

try {
  requirePass(decision);              // throws unless PASS
  await runTheTool();                 // only reached on PASS
} catch (e) {
  if (e instanceof TscBlockedError) stopAndLog(e.decision);
}
```

Builders: `dataEgressContext(...)`, `toolCallContext(...)`, `paymentContext(...)`.
Full [Typed Security Context schema](https://github.com/Shxnque/quesen/tree/main/docs/security-context).
Runnable demo: [`examples/agent_firewall.ts`](examples/agent_firewall.ts).

### Receipt provenance (v1.10, tracked in SDK v0.2.0)

```ts
const verdict = await q.validate({
  domain_age_days: 1,
  engagement_ratio: 0.95,
  scam_keyword_count: 4,
});

console.log(verdict.input_snapshot_hash);
// e.g. "2b0a…" — 64-char lowercase SHA-256 hex over canonical-JSON of the request
//                 (with client_request_id excluded from hash material)
console.log(verdict.commit_sha);
// e.g. "0b77cf…" — 40-char lowercase git SHA of Shxnque/quesen HEAD at decision
//                    time, or the sentinel "unknown"
```

Client-side reconstruction (verify the engine evaluated exactly what you sent):

```ts
async function inputSnapshotHash(payload: Record<string, unknown>): Promise<string> {
  const toHash: Record<string, unknown> = {};
  const keys = Object.keys(payload).sort();
  for (const k of keys) {
    if (k === "client_request_id") continue;
    if (payload[k] === null || payload[k] === undefined) continue;
    toHash[k] = payload[k];
  }
  const canonical = JSON.stringify(toHash);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
```

**Backward compatibility.** Both fields are typed as `string | undefined`. Against
a pre-v1.10 engine they simply won't be set; type-checking stays clean.

### v1.5.0 on-chain enrichment (optional)

Pass `chain` + `contract_address` to enable deterministic on-chain enrichment.
Requires the Quesen server to be started with `QUESEN_ONCHAIN_ENABLED=true`
and per-chain `QUESEN_ONCHAIN_RPC_<SLUG>` set.

```ts
const verdict = await q.validate({
  engagement_ratio: 0.9,
  chain: "base",
  contract_address: "0x4200000000000000000000000000000000000006",
});

if (verdict.onchain_enrichment?.holder_concentration.top1_share ?? 0 > 0.6) {
  // Read the enrichment on the client side too if you want extra logging.
}
```

---

## Errors

All errors extend `QuesenError`:

| Class | Trigger |
|---|---|
| `QuesenAuthError` | 401 (missing/invalid API key) |
| `QuesenValidationError` | 422 (input shape) |
| `QuesenRateLimitError` | 429 (per-key rate limit) |
| `QuesenServerError` | 5xx after retries |
| `QuesenTimeout` | `timeoutMs` exceeded |
| `QuesenTransportError` | network failure |

5xx errors are retried with exponential backoff (default 2 retries). Business
errors (401 / 422 / 429) surface immediately.

---

## Doctrine

This SDK is bound by Quesen's published design principles (see [Shxnque/quesen](https://github.com/Shxnque/quesen)):

- **§2 determinism** — never adds randomness, never adds an LLM in the loop.
- **§11 ecosystem neutrality** — zero runtime dependencies.
- **§12 anti-bureaucracy** — one client, one file, one intent.
- **Receipt provenance forwarded** — `input_snapshot_hash` + `commit_sha` typed on `ValidateResult` (v0.2.0+).

---

## Development

```bash
cd sdks/js
yarn install
yarn test           # vitest
yarn build          # emit dist/ (tsc)
```
