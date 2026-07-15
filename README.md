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
> Every response embeds `engine_version`, `weights`, and `thresholds` — fully
> replayable audit trail.

---

## Install

```bash
npm i quesen-sdk           # or: yarn add quesen-sdk / bun add quesen-sdk
```

---

## Feature surface

- **`.health()`** — liveness probe.
- **`.version()`** — engine + report_schema versions + weights + thresholds + feature flags.
- **`.validate(input)`** — the main decision endpoint.
- **`.simulate(input)`** — counterfactual scoring with `weights_override` / `thresholds_override`.
- **`.report(input)`** — post-decision outcome feedback (v1.1 schema with `realized_pnl`, `venue`, etc.).

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

Fields returned inside `onchain_enrichment`:

- `chain`, `chain_id`, `contract_address`
- `has_code`, `contract_age_days`
- `source_verification.is_verified` (Blockscout)
- `proxy.is_proxy`, `proxy.implementation_address` (EIP-1967)
- `ownership.owner_address`, `ownership.renounced`
- `holder_concentration.top1_share`, `.top5_share`, `.top10_share`
- `status`, `probes_run`, `probes_skipped`, `errors`

Every field is either a concrete value OR `null` with a populated
`unknown_reason` — no ambiguous states.

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

---

## Development

```bash
cd sdks/js
yarn install
yarn test           # vitest
yarn build          # emit dist/ (tsc)
```
