/**
 * Fetch-based Quesen HTTP client — Node 18+, Bun, Deno, browsers.
 *
 * Zero runtime dependencies. Uses `globalThis.fetch` (available on all modern
 * JS runtimes). Retries are limited to network/5xx errors so business errors
 * (401/422/429) surface immediately.
 */

import {
  QuesenAuthError,
  QuesenError,
  QuesenRateLimitError,
  QuesenServerError,
  QuesenTimeout,
  QuesenTransportError,
  QuesenValidationError,
} from "./errors.js";
import type {
  ReportInput,
  ReportResult,
  SimulateInput,
  SimulateResult,
  ValidateInput,
  ValidateResult,
} from "./types.js";
import type { TscContext, TscDecision } from "./tsc.js";

export interface QuesenClientOptions {
  baseUrl: string;
  apiKey?: string;
  /** Milliseconds per request. Default 10000. */
  timeoutMs?: number;
  /** Number of retry attempts on 5xx / network errors. Default 2. */
  retries?: number;
  /** Base backoff in ms. Default 200. */
  retryBackoffMs?: number;
  /** Injected fetch (useful for tests). Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

interface RawErrorBody {
  detail?: string | { msg: string }[];
}

/** Response shape from `POST /sandbox/keys`. */
export interface SandboxKeyResponse {
  api_key: string;
  tier: string;
  price_per_call: number;
  rate_limit_per_min: number;
  starter_credits: number;
  engine_version: string;
  [k: string]: unknown;
}

/**
 * Small deterministic sleep helper. Uses `setTimeout` so it works in every
 * runtime that supports `fetch`.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class QuesenClient {
  readonly baseUrl: string;
  apiKey?: string;
  readonly timeoutMs: number;
  readonly retries: number;
  readonly retryBackoffMs: number;
  private readonly _fetch: typeof fetch;

  constructor(opts: QuesenClientOptions) {
    if (!opts || !opts.baseUrl) {
      throw new QuesenError("baseUrl is required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 10000;
    this.retries = opts.retries ?? 2;
    this.retryBackoffMs = opts.retryBackoffMs ?? 200;
    // Explicit fetch injection preferred; fall back to global. Bind on globalThis
    // to preserve `this` semantics inside the fetch implementation.
    if (opts.fetch) {
      this._fetch = opts.fetch;
    } else if (typeof globalThis.fetch === "function") {
      this._fetch = globalThis.fetch.bind(globalThis);
    } else {
      throw new QuesenError(
        "no fetch implementation found; pass one via opts.fetch (Node <18 or non-standard runtime)",
      );
    }
  }

  private _headers(clientRequestId?: string): Record<string, string> {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "quesen-sdk-js/0.5.0",
    };
    if (this.apiKey) h["X-API-Key"] = this.apiKey;
    if (clientRequestId) h["X-Request-ID"] = clientRequestId;
    return h;
  }

  private _mapError(status: number, requestId: string | undefined, body: unknown): QuesenError {
    const detail =
      typeof body === "object" && body !== null ? (body as RawErrorBody).detail : undefined;
    const msg = typeof detail === "string" ? detail : `quesen ${status}`;
    if (status === 401) return new QuesenAuthError(msg, { status, requestId, detail });
    if (status === 422) return new QuesenValidationError(msg, { status, requestId, detail });
    if (status === 429) return new QuesenRateLimitError(msg, { status, requestId, detail });
    if (status >= 500) return new QuesenServerError(msg, { status, requestId, detail });
    return new QuesenError(msg, { status, requestId, detail });
  }

  private async _request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    clientRequestId?: string,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers = this._headers(clientRequestId);

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      let resp: Response;
      try {
        resp = await this._fetch(url, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (err) {
        clearTimeout(timeout);
        const isAbort = (err as Error).name === "AbortError";
        if (isAbort) {
          if (attempt >= this.retries) throw new QuesenTimeout(`request timed out after ${this.timeoutMs}ms`);
        } else if (attempt >= this.retries) {
          throw new QuesenTransportError((err as Error).message ?? "network error", err);
        }
        await sleep(this.retryBackoffMs * Math.pow(2, attempt));
        continue;
      }
      clearTimeout(timeout);

      const reqId = resp.headers.get("x-request-id") ?? undefined;
      let parsed: unknown;
      const text = await resp.text();
      try {
        parsed = text ? JSON.parse(text) : {};
      } catch {
        parsed = { detail: text };
      }

      if (resp.ok) return parsed as T;

      // Business errors surface immediately (no retry).
      if (resp.status < 500) {
        throw this._mapError(resp.status, reqId, parsed);
      }
      // 5xx: retry with exponential backoff.
      if (attempt >= this.retries) {
        throw this._mapError(resp.status, reqId, parsed);
      }
      await sleep(this.retryBackoffMs * Math.pow(2, attempt));
    }
    // Unreachable in practice — loop always returns or throws.
    throw new QuesenError("request exhausted without response");
  }

  // ---------- public methods ----------

  health(): Promise<{ status: "ok"; engine_version: string }> {
    return this._request("GET", "/health");
  }

  version(): Promise<Record<string, unknown>> {
    return this._request("GET", "/version");
  }

  /**
   * Self-serve a FREE, rate-limited sandbox API key — no signup, no card.
   *
   * Wraps `POST /sandbox/keys` and, by default, configures *this* client to use
   * the returned key for every subsequent call, so a fresh developer goes from
   * install to a real deterministic decision without hunting for an
   * undocumented key-minting step. Returns the full response.
   */
  async createSandboxKey(setOnClient = true): Promise<SandboxKeyResponse> {
    const data = await this._request<SandboxKeyResponse>("POST", "/sandbox/keys", {});
    if (setOnClient && data.api_key) this.apiKey = data.api_key;
    return data;
  }

  validate(input: ValidateInput): Promise<ValidateResult> {
    return this._request<ValidateResult>("POST", "/validate", input, input.client_request_id);
  }

  simulate(input: SimulateInput): Promise<SimulateResult> {
    return this._request<SimulateResult>("POST", "/simulate", input, input.client_request_id);
  }

  report(input: ReportInput): Promise<ReportResult> {
    return this._request<ReportResult>("POST", "/report", input, input.client_request_id);
  }

  /**
   * Agent firewall: evaluate a Typed Security Context (TSC v2).
   *
   * Returns a deterministic PASS / REVIEW / BLOCK / SKIP decision plus an audit
   * receipt. Requires an engine running with `QUESEN_TSC_V2_ENABLED=true`;
   * against an engine without the flag the route is absent (404) and this
   * rejects, fail-closed. Use `requirePass()` / `isAllowed()` from `./tsc`.
   */
  validateTsc(context: TscContext): Promise<TscDecision> {
    return this._request<TscDecision>(
      "POST",
      "/tsc/validate",
      context,
      context.client_request_id,
    );
  }
}
