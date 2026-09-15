/**
 * QuesenFirewall — the highest-ergonomics surface for the agent firewall (JS/TS).
 *
 * Mirrors the Python `QuesenFirewall`: reduce the distance from "interesting" to
 * "I can try this" to a single call. Wraps `QuesenClient.validateTsc` + the TSC
 * context builders. Adds NO decision logic — the engine remains the sole
 * authority. It exists purely to remove boilerplate for the catastrophic-action
 * shapes (data egress / tool call / payment) and to self-onboard a fresh dev.
 *
 *   import { QuesenFirewall } from "quesen-sdk";
 *
 *   const fw = await QuesenFirewall.sandbox("https://web-production-3df26.up.railway.app");
 *   await fw.requirePass({ agent: "my-agent", action: "send_data",
 *                          target: "https://paste.evil", dataClass: "secret" }); // throws
 */

import { QuesenClient, type QuesenClientOptions } from "./client.js";
import {
  dataEgressContext,
  paymentContext,
  toolCallContext,
  requirePass,
  type CapabilityClass,
  type DataClass,
  type Framework,
  type ProvenanceSource,
  type TrustTier,
  type TscContext,
  type TscDecision,
} from "./tsc.js";

const EGRESS_ACTIONS = new Set([
  "send_data", "data_egress", "egress", "exfiltrate", "http_post", "upload",
]);
const PAYMENT_ACTIONS = new Set([
  "payment", "pay", "transfer", "send_funds", "send_money",
]);

export interface FirewallCheckOpts {
  agent?: string;
  /** Friendly action alias. Defaults to "tool_call". */
  action?: string;
  target?: string;
  dataClass?: DataClass | string | (DataClass | string)[];
  capabilityClass?: CapabilityClass | string;
  grantedScopes?: string[];
  requestedScopes?: string[];
  trustTier?: TrustTier;
  destinationTrust?: TrustTier;
  framework?: Framework;
  provenance?: ProvenanceSource;
  injectionSuspected?: boolean;
  injectionPatterns?: string[];
  clientRequestId?: string;
}

function asList(v?: string | string[]): string[] | undefined {
  if (v === undefined || v === null) return undefined;
  return Array.isArray(v) ? [...v] : [v];
}

/** Ergonomic wrapper over the Quesen TSC v2 agent firewall. */
export class QuesenFirewall {
  private readonly client: QuesenClient;

  constructor(client: QuesenClient) {
    this.client = client;
  }

  /**
   * Zero-config firewall — mints a FREE sandbox key automatically.
   * The single frictionless entry point for a fresh developer.
   */
  static async sandbox(
    baseUrl: string,
    opts: Omit<QuesenClientOptions, "baseUrl"> = {},
  ): Promise<QuesenFirewall> {
    const client = new QuesenClient({ baseUrl, ...opts });
    await client.createSandboxKey();
    return new QuesenFirewall(client);
  }

  private _build(o: FirewallCheckOpts): TscContext {
    const act = (o.action ?? "tool_call").toLowerCase();
    const classes = asList(o.dataClass as string | string[] | undefined);
    if (EGRESS_ACTIONS.has(act)) {
      return dataEgressContext({
        dataClasses: (classes ?? ["unknown"]) as string[],
        to: o.target ?? "unknown",
        destinationTrust: o.destinationTrust ?? "unverified",
        framework: o.framework,
        provenance: o.provenance ?? "adapter_derived",
        clientRequestId: o.clientRequestId,
      });
    }
    if (PAYMENT_ACTIONS.has(act)) {
      return paymentContext({
        grantedScopes: o.grantedScopes,
        trustTier: o.trustTier && o.trustTier !== "unknown" ? o.trustTier : "unverified",
        framework: o.framework,
        provenance: o.provenance ?? "client_asserted",
        clientRequestId: o.clientRequestId,
      });
    }
    return toolCallContext({
      capabilityClass: o.capabilityClass ?? "other",
      grantedScopes: o.grantedScopes,
      requestedScopes: o.requestedScopes,
      trustTier: o.trustTier ?? "unknown",
      framework: o.framework,
      provenance: o.provenance ?? "adapter_derived",
      injectionSuspected: o.injectionSuspected,
      injectionPatterns: o.injectionPatterns,
      clientRequestId: o.clientRequestId,
    });
  }

  /** Return the raw TscDecision for a described action (no throwing). */
  check(opts: FirewallCheckOpts): Promise<TscDecision> {
    return this.client.validateTsc(this._build(opts));
  }

  /** True only if the engine returned an explicit PASS (fail-closed). */
  async allows(opts: FirewallCheckOpts): Promise<boolean> {
    return (await this.check(opts)).decision === "PASS";
  }

  /** Throw TscBlockedError unless the described action is a PASS. */
  async requirePass(opts: FirewallCheckOpts): Promise<TscDecision> {
    return requirePass(await this.check(opts));
  }

  /**
   * Enforcement mode: wrap an async function so it is *gated*, not merely advised.
   * The wrapped callable does not execute unless the engine returns PASS
   * (fail-closed on BLOCK/REVIEW/SKIP and on transport error). The last verdict
   * is exposed as `wrapped.lastDecision` for auditing.
   *
   *   const sendFunds = fw.guard(
   *     { action: "payment", trustTier: "unverified" },
   *     async (to: string, amount: number) => { ...  }
   *   );
   *   await sendFunds("0xabc", 5); // throws TscBlockedError unless PASS
   */
  guard<A extends unknown[], R>(
    opts: FirewallCheckOpts,
    fn: (...args: A) => Promise<R>,
  ): ((...args: A) => Promise<R>) & { lastDecision: TscDecision | null } {
    const self = this;
    type Guarded = ((...args: A) => Promise<R>) & { lastDecision: TscDecision | null };
    const wrapped = (async (...args: A): Promise<R> => {
      const decision = await self.check(opts);
      wrapped.lastDecision = decision;
      requirePass(decision); // throws on anything but PASS
      return fn(...args);
    }) as unknown as Guarded;
    wrapped.lastDecision = null;
    return wrapped;
  }
}
