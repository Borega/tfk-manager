import type {
  ServerAnalysisDashboardResponse,
  ServerBucketGrain,
  ServerClientResult,
  ServerEventsQuery,
  ServerEventsResponse,
  ServerFreshnessResponse,
  ServerSourceType,
  ServerTrendsQuery,
  ServerTrendsResponse,
} from "./serverAnalysisContracts";

export type AnalysisMode = "server" | "fallback-local" | "local-only";

export type ServerFirstWindow = {
  startAt: string;
  endAt: string;
  sourceType?: ServerSourceType;
  bucketGrain?: ServerBucketGrain;
  eventLimit?: number;
};

export type ServerFirstClient = {
  getFreshness: () => Promise<ServerClientResult<ServerFreshnessResponse>>;
  getTrends: (query: ServerTrendsQuery) => Promise<ServerClientResult<ServerTrendsResponse>>;
  getEvents: (query: ServerEventsQuery) => Promise<ServerClientResult<ServerEventsResponse>>;
  getAnalysisDashboard: (query: { startAt: string; endAt: string; bucketGrain?: ServerBucketGrain }) => Promise<ServerClientResult<ServerAnalysisDashboardResponse>>;
};

export type ServerFirstSuccess = {
  mode: "server";
  freshness: ServerFreshnessResponse;
  trends: ServerTrendsResponse;
  events: ServerEventsResponse;
  dashboard: ServerAnalysisDashboardResponse;
};

export type ServerFirstFallback = {
  mode: "fallback-local";
  reason: string;
  errorCode: string;
  stage: "freshness" | "trends" | "events" | "dashboard" | "unexpected";
  freshness?: ServerFreshnessResponse;
};

export type ServerFirstResult = ServerFirstSuccess | ServerFirstFallback;

export type RunServerFirstAnalysisArgs = {
  client: ServerFirstClient;
  window: ServerFirstWindow;
  onFallbackLocal?: () => Promise<void> | void;
};

function fallbackFromError(
  stage: ServerFirstFallback["stage"],
  result: ServerClientResult<unknown>,
  options: { freshness?: ServerFreshnessResponse } = {},
): ServerFirstFallback {
  if (result.ok) {
    return {
      mode: "fallback-local",
      reason: "unexpected success payload",
      errorCode: "unexpected_success_payload",
      stage,
      ...options,
    };
  }
  return {
    mode: "fallback-local",
    reason: result.error.message,
    errorCode: result.error.errorCode,
    stage,
    ...options,
  };
}

async function runFallbackHook(onFallbackLocal?: () => Promise<void> | void): Promise<void> {
  if (!onFallbackLocal) return;
  await onFallbackLocal();
}

export async function runServerFirstAnalysis({
  client,
  window,
  onFallbackLocal,
}: RunServerFirstAnalysisArgs): Promise<ServerFirstResult> {
  let freshnessSnapshot: ServerFreshnessResponse | undefined;

  try {
    const freshness = await client.getFreshness();
    if (!freshness.ok) {
      await runFallbackHook(onFallbackLocal);
      return fallbackFromError("freshness", freshness);
    }
    freshnessSnapshot = freshness.data;

    const trends = await client.getTrends({
      startAt: window.startAt,
      endAt: window.endAt,
      sourceType: window.sourceType,
      bucketGrain: window.bucketGrain,
    });
    if (!trends.ok) {
      await runFallbackHook(onFallbackLocal);
      return fallbackFromError("trends", trends, { freshness: freshnessSnapshot });
    }

    const events = await client.getEvents({
      startAt: window.startAt,
      endAt: window.endAt,
      sourceType: window.sourceType,
      limit: window.eventLimit,
    });
    if (!events.ok) {
      await runFallbackHook(onFallbackLocal);
      return fallbackFromError("events", events, { freshness: freshnessSnapshot });
    }

    const dashboard = await client.getAnalysisDashboard({
      startAt: window.startAt,
      endAt: window.endAt,
      bucketGrain: window.bucketGrain,
    });
    if (!dashboard.ok) {
      await runFallbackHook(onFallbackLocal);
      return fallbackFromError("dashboard", dashboard, { freshness: freshnessSnapshot });
    }

    return {
      mode: "server",
      freshness: freshness.data,
      trends: trends.data,
      events: events.data,
      dashboard: dashboard.data,
    };
  } catch (error) {
    await runFallbackHook(onFallbackLocal);
    return {
      mode: "fallback-local",
      reason: String(error),
      errorCode: "server_first_unexpected_error",
      stage: "unexpected",
      freshness: freshnessSnapshot,
    };
  }
}
