# Changelog

All notable changes to `quesen-sdk` (JavaScript / TypeScript) will be documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-09-05 · Offline verdict replay (recomputability before adoption)

### Added
- **`replay(context)`** — recompute the TSC v2 egress/authority verdict
  `{decision, reason_codes, input_snapshot_hash}` **entirely offline, zero network,
  zero dependency** (Node built-in crypto only), from a TypeScript port of the public
  reference evaluator (`src/reference.ts`). Byte-for-byte identical to the Python SDK
  and the engine — verified against the live engine for BLOCK / REVIEW / PASS shapes.
- **`verifyReceipt(receipt, { recomputeRequest })`** — independently REPLAY the verdict
  offline and assert it matches the receipt; `ReceiptVerification` gains a `recomputed`
  field. A mismatch flips `ok` to `false` (fail-closed via `requireReceipt`).
- Also exported: `referenceEvaluate`, `referenceNormalize`, `referenceCanonicalJson`,
  `referenceInputSnapshotHash`, `TscReferenceError`, `REFERENCE_VERSION`.
- Answers BEA criticism-ledger C-003 (sequant) / C-004 (loopx) in the JS ecosystem:
  the hosted engine becomes an optimisation, not a trust dependency, for this subset.

## [0.5.0] — 2026-09-03 · Enforcement + independently-verifiable receipts

### Added
- **`QuesenFirewall.guard(...)`** — fail-closed enforcement wrapper (parity with Python).
- **`verifyReceipt` / `requireReceipt` / `canonicalReceiptBytes`** — client-side receipt
  verification: structural integrity plus optional Ed25519 signature check via Node crypto.

## [0.4.0] — 2026-08-27 · QuesenFirewall + frictionless onboarding (parity with Python 0.4.1)

### Added
- **`QuesenFirewall`** — one-call agent-firewall surface mirroring the Python SDK:
  `fw.requirePass({ agent, action: "send_data", target, dataClass: "secret" })`
  throws `TscBlockedError` on anything but PASS. Friendly `action` aliases route
  to the correct TSC builder (egress / payment / tool_call).
- **`QuesenFirewall.sandbox(baseUrl)`** — zero-config entry point that mints a FREE
  sandbox key automatically, so a fresh developer goes from `npm i` to a real
  deterministic BLOCK in one call (no signup, no card, no undocumented key step).
- **`QuesenClient.createSandboxKey()`** — wraps `POST /sandbox/keys`; by default
  applies the returned key to the client for subsequent calls.

### Fixed
- Onboarding blocker: the hosted engine requires a key (no open mode); the SDK
  now self-serves one. README quickstart rewritten to the true onboarding path.
- `User-Agent` bumped `quesen-sdk-js/0.3.0` → `0.4.0`.

## [0.3.0] — 2026-08-26 · TSC v2 agent firewall (tracks engine v1.10.0 + ADR-042)

### Added
- **`client.validateTsc(context)`** — calls the engine's `POST /tsc/validate`
  route and returns a typed **`TscDecision`** (`PASS` / `REVIEW` / `BLOCK` /
  `SKIP`) with the full audit receipt (`risk_score`, `confidence`, `reasons`,
  `tags`, `engine_version`, `commit_sha`, `input_snapshot_hash`, `request_id`).
- **`quesen-sdk` TSC surface**: `dataEgressContext`, `toolCallContext`,
  `paymentContext` builders; `TscContext` / `TscDecision` / `TscReason` types;
  `isAllowed`, `reasonCodes`, `requirePass` helpers; `TscBlockedError`.
- Example `examples/agent_firewall.ts`; self-contained `tests/tsc.test.ts`.

### Changed
- `VERSION` `0.2.0` → `0.3.0`; User-Agent → `quesen-sdk-js/0.3.0`.

### Backward compatibility
- Fully additive; all v1 methods and types unchanged. `validateTsc` is inert
  against engines without `QUESEN_TSC_V2_ENABLED` (route absent → rejects).

## [0.2.0] — 2026-07-31 · Receipt provenance (tracks engine v1.10.0)

### Added
- **`ValidateResult.input_snapshot_hash?: string`** — lowercase 64-char SHA-256
  hex over canonical-JSON of the received request payload (with
  `client_request_id` excluded from hash material). Undefined against pre-v1.10
  engines.
- **`ValidateResult.commit_sha?: string`** — 40-char lowercase git SHA of the
  engine ruleset live at decision time (or the sentinel `"unknown"`). Undefined
  against pre-v1.10 engines.
- Client-side hash reconstruction snippet documented in README.

### Changed
- `VERSION` bumped `0.1.0` → `0.2.0`.
- User-Agent header bumped `quesen-sdk-js/0.1.0` → `quesen-sdk-js/0.2.0`.
- README status line: tracks Quesen engine v1.9.0 → v1.10.0.

### Backward compatibility
- Fully additive. Both new fields are typed as optional; existing code that
  never references them keeps compiling and running unchanged.

### Cross-references
- Engine ADR: `Shxnque/Quesen-sib/enshrine/066-adr-041-receipt-provenance.md`
- Public API contract: https://github.com/Shxnque/quesen/blob/main/docs/api-reference.md#receipt-provenance-v110
- Engine tag: [`v1.10.0-rc1`](https://github.com/Shxnque/quesen)

## [0.1.0] — 2026-07-16 · Initial release
- Fetch-based `QuesenClient` for Node 18+, Bun, Deno, browsers.
- Zero runtime dependencies.
- Full typed response envelopes.

[0.2.0]: https://github.com/Shxnque/quesen-sdk-js/releases/tag/v0.2.0
[0.1.0]: https://github.com/Shxnque/quesen-sdk-js/releases/tag/v0.1.0
