# Changelog

All notable changes to `quesen-sdk` (JavaScript / TypeScript) will be documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
