export type SourcePolicyKey = "leases" | "webfilter-ui" | "firewall-stream";

type RetryPolicy = {
  baseMs: number;
  maxMs: number;
};

export const SOURCE_STALE_MS: Record<SourcePolicyKey, number> = {
  leases: 10 * 60 * 1000,
  "webfilter-ui": 3 * 60 * 1000,
  "firewall-stream": 75 * 1000,
};

export const SOURCE_POLL_MS: Record<SourcePolicyKey, number> = {
  leases: 2 * 60 * 1000,
  "webfilter-ui": 30 * 1000,
  "firewall-stream": 20 * 1000,
};

export type WebfilterPollContext = {
  isInteractiveView: boolean;
  isDocumentVisible: boolean;
  hasRecentError: boolean;
};

const SOURCE_RETRY_POLICY: Record<SourcePolicyKey, RetryPolicy> = {
  leases: { baseMs: 10_000, maxMs: 3 * 60_000 },
  "webfilter-ui": { baseMs: 8_000, maxMs: 2 * 60_000 },
  "firewall-stream": { baseMs: 5_000, maxMs: 60_000 },
};

export function nextRetryDelayMs(source: SourcePolicyKey, attempt: number): number {
  const policy = SOURCE_RETRY_POLICY[source];
  const exponent = Math.max(0, Math.floor(attempt));
  const raw = policy.baseMs * (2 ** exponent);
  return Math.min(policy.maxMs, raw);
}

export function isRetryReady(nextRetryAtIso: string | null, nowMillis: number = Date.now()): boolean {
  if (!nextRetryAtIso) return true;
  const ts = Date.parse(nextRetryAtIso);
  if (Number.isNaN(ts)) return true;
  return nowMillis >= ts;
}

export function formatRetryWaitSeconds(nextRetryAtIso: string | null, nowMillis: number = Date.now()): number {
  if (!nextRetryAtIso) return 0;
  const ts = Date.parse(nextRetryAtIso);
  if (Number.isNaN(ts)) return 0;
  const msLeft = ts - nowMillis;
  if (msLeft <= 0) return 0;
  return Math.ceil(msLeft / 1000);
}

export function getWebfilterPollIntervalMs(context: WebfilterPollContext): number {
  if (context.isInteractiveView && context.isDocumentVisible && !context.hasRecentError) return 3_000;
  if (context.isInteractiveView && context.isDocumentVisible) return 5_000;
  if (context.isInteractiveView && !context.isDocumentVisible) return 12_000;
  if (!context.isInteractiveView && context.isDocumentVisible) return 20_000;
  return SOURCE_POLL_MS["webfilter-ui"];
}

export function applyPollJitterMs(
  baseMs: number,
  jitterFraction: number = 0.15,
  random: () => number = Math.random,
): number {
  const safeBase = Math.max(2_000, Math.floor(baseMs));
  const fraction = Math.min(0.5, Math.max(0, jitterFraction));
  const delta = safeBase * fraction;
  const factor = random() * 2 - 1;
  const jittered = safeBase + delta * factor;
  return Math.max(2_000, Math.round(jittered));
}
