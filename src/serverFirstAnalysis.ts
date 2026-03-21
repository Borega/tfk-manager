import type {
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
};

export type ServerFirstSuccess = {
  mode: "server";
  freshness: ServerFreshnessResponse;
  trends: ServerTrendsResponse;
  events: ServerEventsResponse;
};

export type ServerFirstFallback = {
  mode: "fallback-local";
  reason: string;
  errorCode: string;
  stage: "freshness" | "trends" | "events" | "unexpected";
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
): ServerFirstFallback {
  if (result.ok) {
    return {
      mode: "fallback-local",
      reason: "unexpected success payload",
      errorCode: "unexpected_success_payload",
      stage,
    };
  }
  return {
    mode: "fallback-local",
    reason: result.error.message,
    errorCode: result.error.errorCode,
    stage,
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
  try {
    const freshness = await client.getFreshness();
    if (!freshness.ok) {
      await runFallbackHook(onFallbackLocal);
      return fallbackFromError("freshness", freshness);
    }

    const trends = await client.getTrends({
      startAt: window.startAt,
      endAt: window.endAt,
      sourceType: window.sourceType,
      bucketGrain: window.bucketGrain,
    });
    if (!trends.ok) {
      await runFallbackHook(onFallbackLocal);
      return fallbackFromError("trends", trends);
    }

    const events = await client.getEvents({
      startAt: window.startAt,
      endAt: window.endAt,
      sourceType: window.sourceType,
      limit: window.eventLimit,
    });
    if (!events.ok) {
      await runFallbackHook(onFallbackLocal);
      return fallbackFromError("events", events);
    }

    return {
      mode: "server",
      freshness: freshness.data,
      trends: trends.data,
      events: events.data,
    };
  } catch (error) {
    await runFallbackHook(onFallbackLocal);
    return {
      mode: "fallback-local",
      reason: String(error),
      errorCode: "server_first_unexpected_error",
      stage: "unexpected",
    };
  }
}
