/**
 * Runnable example — Node / Bun / Deno.
 *
 *     export QUESEN_BASE_URL=https://your-quesen-endpoint
 *     export QUESEN_API_KEY=sk_test_xxx    # if the server has key registry enabled
 *     node examples/node.mjs
 */

import { QuesenClient } from "../dist/index.js";

const q = new QuesenClient({
  baseUrl: process.env.QUESEN_BASE_URL ?? "http://localhost:8000",
  apiKey: process.env.QUESEN_API_KEY,
});

const health = await q.health();
console.log("HEALTH:", health);

const rug = await q.validate({
  domain_age_days: 1,
  engagement_ratio: 0.95,
  scam_keyword_count: 4,
});
console.log("RUG PATTERN:", rug.decision, rug.risk_score, rug.conflict_triggers);

// On-chain enrichment (server must have QUESEN_ONCHAIN_ENABLED=true).
try {
  const enriched = await q.validate({
    engagement_ratio: 0.9,
    chain: "base",
    contract_address: "0x4200000000000000000000000000000000000006",
  });
  console.log("BASE:WETH →", enriched.decision, enriched.onchain_enrichment?.status);
} catch (err) {
  console.log("enrichment path skipped:", (err as Error).message);
}
