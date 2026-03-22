import {
  isServerApiErrorEnvelope,
  type ServerApiErrorEnvelope,
  type ServerClientResult,
  type ServerEventsQuery,
  type ServerEventsResponse,
  type ServerFreshnessResponse,
  type ServerTrendsQuery,
  type ServerTrendsResponse,
} from "./serverAnalysisContracts";
import {
  refreshServerSession,
  type RefreshServerSessionArgs,
  type RefreshServerSessionResult,
  type ServerSession,
  type ServerSessionTokens,
} from "./serverAuthSession";

export type CreateServerAnalysisClientArgs = {
  baseUrl: string;
  session: ServerSession;
  fetchImpl?: typeof fetch;
  refreshSession?: (args: RefreshServerSessionArgs) => Promise<RefreshServerSessionResult>;
  onSessionUpdated?: (tokens: ServerSessionTokens) => void;
};

type RequestOptions = {
  method: "GET" | "POST";
  path: string;
  body?: unknown;
};

function normalizeBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object") return {};
  return value as Record<string, unknown>;
}

function buildError(
  status: number,
  payload: unknown,
  fallbackCode: string,
  fallbackMessage: string,
  fallbackRequestId: string,
): ServerApiErrorEnvelope {
  if (isServerApiErrorEnvelope(payload)) return payload;
  const objectPayload = asObject(payload);
  return {
    status,
    errorCode: typeof objectPayload.errorCode === "string" ? objectPayload.errorCode : fallbackCode,
    message: typeof objectPayload.message === "string" ? objectPayload.message : fallbackMessage,
    requestId: typeof objectPayload.requestId === "string" ? objectPayload.requestId : fallbackRequestId,
    details: objectPayload.details as Record<string, unknown> | null | undefined,
  };
}

async function safeJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text.trim()) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { message: text };
  }
}

function toQueryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    search.set(key, String(value));
  });
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

function unwrapFreshnessPayload(payload: unknown): ServerFreshnessResponse | null {
  const objectPayload = asObject(payload);
  if (typeof objectPayload.status !== "number") return null;
  if (!objectPayload.data || typeof objectPayload.data !== "object") return null;
  return objectPayload as ServerFreshnessResponse;
}

export function createServerAnalysisClient({
  baseUrl,
  session,
  fetchImpl = fetch,
  refreshSession = refreshServerSession,
  onSessionUpdated,
}: CreateServerAnalysisClientArgs) {
  const base = normalizeBaseUrl(baseUrl);

  const callJson = async <T>(options: RequestOptions, allowRefresh: boolean): Promise<ServerClientResult<T>> => {
    const accessToken = session.getAccessToken();
    if (!accessToken) {
      return {
        ok: false,
        status: 401,
        error: {
          status: 401,
          errorCode: "token_invalid",
          message: "missing access token",
          requestId: "server-analysis-client-auth",
          details: { reason: "no_access_token" },
        },
      };
    }

    const endpoint = `${base}${options.path}`;

    let response: Response;
    try {
      response = await fetchImpl(endpoint, {
        method: options.method,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      });
    } catch (error) {
      return {
        ok: false,
        status: 503,
        error: {
          status: 503,
          errorCode: "server_unreachable",
          message: "server request failed",
          requestId: "server-analysis-client-network",
          details: { reason: String(error) },
        },
      };
    }

    const payload = await safeJson(response);

    if (response.status === 401 && allowRefresh) {
      const refreshed = await refreshSession({ baseUrl: base, session, fetchImpl });
      if (!refreshed.ok) {
        return { ok: false, status: refreshed.error.status, error: refreshed.error };
      }
      onSessionUpdated?.(refreshed.tokens);
      return callJson<T>(options, false);
    }

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: buildError(response.status, payload, "request_failed", "server request failed", "server-analysis-client"),
      };
    }

    return {
      ok: true,
      status: response.status,
      data: payload as T,
    };
  };

  const getEvents = (query: ServerEventsQuery): Promise<ServerClientResult<ServerEventsResponse>> => {
    const params = toQueryString({
      startAt: query.startAt,
      endAt: query.endAt,
      sourceType: query.sourceType,
      cursor: query.cursor,
      limit: query.limit,
    });

    return callJson<ServerEventsResponse>({
      method: "GET",
      path: `/api/history/events${params}`,
    }, true);
  };

  const getTrends = (query: ServerTrendsQuery): Promise<ServerClientResult<ServerTrendsResponse>> => {
    const params = toQueryString({
      startAt: query.startAt,
      endAt: query.endAt,
      sourceType: query.sourceType,
      bucketGrain: query.bucketGrain,
    });

    return callJson<ServerTrendsResponse>({
      method: "GET",
      path: `/api/history/trends${params}`,
    }, true);
  };

  const getFreshness = async (): Promise<ServerClientResult<ServerFreshnessResponse>> => {
    const response = await callJson<unknown>({
      method: "GET",
      path: "/api/status/freshness",
    }, true);

    if (!response.ok) {
      return response;
    }

    const payload = unwrapFreshnessPayload(response.data);
    if (!payload) {
      return {
        ok: false,
        status: 502,
        error: {
          status: 502,
          errorCode: "freshness_contract_invalid",
          message: "freshness response contract invalid",
          requestId: "server-analysis-client-freshness",
          details: asObject(response.data),
        },
      };
    }

    return {
      ok: true,
      status: response.status,
      data: payload,
    };
  };

  return {
    getEvents,
    getTrends,
    getFreshness,
  };
}
