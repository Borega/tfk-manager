import {
  isServerApiErrorEnvelope,
  type ServerApiErrorEnvelope,
} from "./serverAnalysisContracts";

export type ServerSessionTokens = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: string;
  refreshExpiresAt: string;
  role?: string;
};

export type ServerSession = {
  getTokens: () => ServerSessionTokens | null;
  setTokens: (tokens: ServerSessionTokens) => void;
  clear: () => void;
  getAccessToken: () => string | null;
  getRefreshToken: () => string | null;
  isAccessTokenExpired: (nowMillis?: number) => boolean;
};

export type RefreshServerSessionArgs = {
  baseUrl: string;
  session: ServerSession;
  fetchImpl?: typeof fetch;
};

export type RefreshServerSessionResult =
  | { ok: true; tokens: ServerSessionTokens }
  | { ok: false; error: ServerApiErrorEnvelope };

function normalizeBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

function parseIsoMillis(value: string): number {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object") return {};
  return value as Record<string, unknown>;
}

function normalizeErrorEnvelope(
  status: number,
  payload: unknown,
  fallbackCode: string,
  fallbackMessage: string,
): ServerApiErrorEnvelope {
  if (isServerApiErrorEnvelope(payload)) return payload;
  const objectPayload = asObject(payload);
  return {
    status,
    errorCode: typeof objectPayload.errorCode === "string" ? objectPayload.errorCode : fallbackCode,
    message: typeof objectPayload.message === "string" ? objectPayload.message : fallbackMessage,
    requestId: typeof objectPayload.requestId === "string" ? objectPayload.requestId : "server-auth-session",
    details: objectPayload.details as Record<string, unknown> | null | undefined,
  };
}

function extractTokens(payload: unknown, fallbackRole?: string): ServerSessionTokens | null {
  const objectPayload = asObject(payload);
  const accessToken = objectPayload.accessToken;
  const refreshToken = objectPayload.refreshToken;
  const accessExpiresAt = objectPayload.accessExpiresAt;
  const refreshExpiresAt = objectPayload.refreshExpiresAt;

  if (
    typeof accessToken !== "string"
    || typeof refreshToken !== "string"
    || typeof accessExpiresAt !== "string"
    || typeof refreshExpiresAt !== "string"
  ) {
    return null;
  }

  return {
    accessToken,
    refreshToken,
    accessExpiresAt,
    refreshExpiresAt,
    role: typeof objectPayload.role === "string" ? objectPayload.role : fallbackRole,
  };
}

async function safeParseJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text.trim()) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { message: text };
  }
}

export function createServerSession(initial: ServerSessionTokens | null = null): ServerSession {
  let state: ServerSessionTokens | null = initial ? { ...initial } : null;

  return {
    getTokens: () => (state ? { ...state } : null),
    setTokens: (tokens) => {
      state = { ...tokens };
    },
    clear: () => {
      state = null;
    },
    getAccessToken: () => state?.accessToken ?? null,
    getRefreshToken: () => state?.refreshToken ?? null,
    isAccessTokenExpired: (nowMillis = Date.now()) => {
      if (!state) return true;
      const expiresAt = parseIsoMillis(state.accessExpiresAt);
      if (!Number.isFinite(expiresAt)) return true;
      return nowMillis >= expiresAt;
    },
  };
}

export async function refreshServerSession({
  baseUrl,
  session,
  fetchImpl = fetch,
}: RefreshServerSessionArgs): Promise<RefreshServerSessionResult> {
  const refreshToken = session.getRefreshToken();
  const currentRole = session.getTokens()?.role;
  if (!refreshToken) {
    return {
      ok: false,
      error: {
        status: 401,
        errorCode: "token_invalid",
        message: "missing refresh token",
        requestId: "refresh-missing-token",
        details: { reason: "no_refresh_token" },
      },
    };
  }

  const endpoint = `${normalizeBaseUrl(baseUrl)}/api/auth/refresh`;

  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refreshToken }),
    });
  } catch (error) {
    return {
      ok: false,
      error: {
        status: 503,
        errorCode: "server_unreachable",
        message: "server refresh request failed",
        requestId: "refresh-network-error",
        details: { reason: String(error) },
      },
    };
  }

  const payload = await safeParseJson(response);
  if (!response.ok) {
    return {
      ok: false,
      error: normalizeErrorEnvelope(response.status, payload, "refresh_failed", "refresh request failed"),
    };
  }

  const tokens = extractTokens(payload, currentRole);
  if (!tokens) {
    return {
      ok: false,
      error: {
        status: 502,
        errorCode: "refresh_contract_invalid",
        message: "refresh response missing token fields",
        requestId: "refresh-invalid-response",
        details: asObject(payload),
      },
    };
  }

  session.setTokens(tokens);
  return { ok: true, tokens };
}
