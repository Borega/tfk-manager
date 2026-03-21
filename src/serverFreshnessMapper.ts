import type { AnalysisMode } from "./serverFirstAnalysis";
import type { ServerFreshnessResponse } from "./serverAnalysisContracts";

export type ServerFreshnessCard = {
  key: string;
  status: "idle" | "healthy" | "stale" | "error";
  label: string;
  detail: string;
  lastSuccessIso: string | null;
};

export type ServerAnalysisModeBadge = {
  mode: AnalysisMode;
  label: string;
  tone: "healthy" | "warning" | "muted";
};

export function toServerAnalysisModeBadge(mode: AnalysisMode): ServerAnalysisModeBadge {
  if (mode === "server") {
    return {
      mode,
      label: "Server-first",
      tone: "healthy",
    };
  }
  if (mode === "fallback-local") {
    return {
      mode,
      label: "Fallback local",
      tone: "warning",
    };
  }
  return {
    mode,
    label: "Local only",
    tone: "muted",
  };
}

function toCardStatus(state: string): ServerFreshnessCard["status"] {
  const normalized = state.trim().toLowerCase();
  if (normalized === "healthy") return "healthy";
  if (normalized === "degraded" || normalized === "stale") return "stale";
  if (normalized === "unknown") return "idle";
  return "error";
}

export function mapServerFreshnessToSourceHealth(
  freshness: ServerFreshnessResponse | null,
  options: {
    nowMillis?: number;
    errorMessage?: string | null;
  } = {},
): ServerFreshnessCard[] {
  const nowMillis = options.nowMillis ?? Date.now();

  if (options.errorMessage) {
    return [{
      key: "server-api",
      status: "error",
      label: "Server API",
      detail: options.errorMessage,
      lastSuccessIso: null,
    }];
  }

  if (!freshness) {
    return [{
      key: "server-api",
      status: "idle",
      label: "Server API",
      detail: "No successful server freshness sync yet",
      lastSuccessIso: null,
    }];
  }

  const generatedAt = freshness.data.generatedAt;
  const generatedAtMs = Date.parse(generatedAt);
  const staleMillis = 2 * 60 * 1000;
  const overallStale = Number.isFinite(generatedAtMs) && nowMillis - generatedAtMs > staleMillis;

  const cards: ServerFreshnessCard[] = freshness.data.sources.map((source) => ({
    key: source.sourceKey,
    status: toCardStatus(source.state),
    label: `Server ${source.sourceKey}`,
    detail: `State ${source.state} · Lag ${source.lagSeconds ?? "?"}s`,
    lastSuccessIso: generatedAt,
  }));

  cards.unshift({
    key: "server-api",
    status: overallStale ? "stale" : "healthy",
    label: "Server API",
    detail: `${freshness.data.overallSeverity} · ${freshness.data.fallbackGuidance.reason}`,
    lastSuccessIso: generatedAt,
  });

  return cards;
}
