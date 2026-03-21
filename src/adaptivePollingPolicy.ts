import type { SourcePolicyKey } from "./sourcePollingPolicy";

export type AdaptiveHealthStatus = "idle" | "healthy" | "stale" | "error";

export type AdaptivePollRequest = {
  source: SourcePolicyKey;
  baseIntervalMs: number;
  healthStatus: AdaptiveHealthStatus;
  backlogSize: number;
  retryAttempt: number;
};

export type AdaptivePollDecision = {
  source: SourcePolicyKey;
  intervalMs: number;
  backoffCeilingMs: number;
  loadMode: "normal" | "recovery" | "degraded";
  reasons: string[];
};

function clampFiniteInt(value: number, fallback: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

function classifyBacklog(backlogSize: number): "low" | "medium" | "high" {
  if (backlogSize >= 500) return "high";
  if (backlogSize >= 120) return "medium";
  return "low";
}

export function resolveAdaptivePollPolicy(request: AdaptivePollRequest): AdaptivePollDecision {
  const baseIntervalMs = clampFiniteInt(request.baseIntervalMs, 2000, 2000, 5 * 60_000);
  const retryAttempt = clampFiniteInt(request.retryAttempt, 0, 0, 100);
  const backlogSize = clampFiniteInt(request.backlogSize, 0, 0, 1_000_000);
  const backlogLevel = classifyBacklog(backlogSize);

  let multiplier = 1;
  const reasons: string[] = [];

  if (request.healthStatus === "stale") {
    multiplier *= 1.4;
    reasons.push("source-stale");
  }

  if (request.healthStatus === "error") {
    multiplier *= 1.9;
    reasons.push("source-error");
  }

  if (backlogLevel === "medium") {
    multiplier *= 1.15;
    reasons.push("backlog-medium");
  }

  if (backlogLevel === "high") {
    multiplier *= 1.35;
    reasons.push("backlog-high");
  }

  if (retryAttempt >= 3) {
    multiplier *= 1.2;
    reasons.push("retry-escalation");
  }

  const cappedInterval = clampFiniteInt(
    Math.round(baseIntervalMs * multiplier),
    baseIntervalMs,
    2000,
    Math.max(baseIntervalMs, baseIntervalMs * 4),
  );

  const backoffCeilingMs = clampFiniteInt(
    Math.round(Math.max(cappedInterval * 5, baseIntervalMs * 3)),
    baseIntervalMs * 3,
    baseIntervalMs,
    10 * 60_000,
  );

  const loadMode = request.healthStatus === "error" || backlogLevel === "high"
    ? "degraded"
    : retryAttempt > 0 || request.healthStatus === "stale"
    ? "recovery"
    : "normal";

  return {
    source: request.source,
    intervalMs: cappedInterval,
    backoffCeilingMs,
    loadMode,
    reasons,
  };
}
