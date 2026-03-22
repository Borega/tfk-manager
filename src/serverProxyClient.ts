import {
  isServerApiErrorEnvelope,
  type ServerApiErrorEnvelope,
  type ServerClientResult,
} from "./serverAnalysisContracts";
import {
  refreshServerSession,
  type RefreshServerSessionArgs,
  type RefreshServerSessionResult,
  type ServerSession,
  type ServerSessionTokens,
} from "./serverAuthSession";

export type ProxyOperationType =
  | "getDynamicLeases"
  | "getStaticLeases"
  | "getFirewallSnapshot"
  | "getWebfilterLogs"
  | "testWebfilterLogin"
  | "addStaticLease"
  | "updateStaticLease"
  | "deleteStaticLease"
  | "moveDynamicToStatic"
  | "updateStaticFromDynamic";

export type ProxyExecuteRequest = {
  operation: ProxyOperationType;
  payload: Record<string, unknown>;
  requestNonce: string;
  requestTimestamp: string;
  requestAudience: string;
};

export type ProxyExecuteEnvelope<TResult> = {
  requestId: string;
  operation: ProxyOperationType;
  scope: string;
  result: TResult;
};

export type ProxyExecuteResult<TResult> = ServerClientResult<ProxyExecuteEnvelope<TResult>>;

export type CreateServerProxyClientArgs = {
  baseUrl: string;
  session: ServerSession;
  sharedSecret: string;
  requestAudience?: string;
  fetchImpl?: typeof fetch;
  refreshSession?: (args: RefreshServerSessionArgs) => Promise<RefreshServerSessionResult>;
  onSessionUpdated?: (tokens: ServerSessionTokens) => void;
  nowFactory?: () => Date;
  nonceFactory?: () => string;
};

type RequestOptions = {
  operation: ProxyOperationType;
  payload: Record<string, unknown>;
};

const DEFAULT_AUDIENCE = "tfk-manager-server";

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

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort((a, b) => a.localeCompare(b));
    const sortedRecord: Record<string, unknown> = {};
    sortedKeys.forEach((key) => {
      sortedRecord[key] = sortJsonValue(record[key]);
    });
    return sortedRecord;
  }
  return value;
}

function canonicalPayload(payload: Record<string, unknown>): string {
  return JSON.stringify(sortJsonValue(payload));
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (item) => item.toString(16).padStart(2, "0")).join("");
}

function toHex(value: ArrayBuffer): string {
  return Array.from(new Uint8Array(value), (item) => item.toString(16).padStart(2, "0")).join("");
}

export async function buildProxySignature(secret: string, request: ProxyExecuteRequest): Promise<string> {
  if (!secret.trim()) {
    throw new Error("proxy_shared_secret_missing");
  }
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("proxy_subtle_crypto_missing");
  }

  const signatureBase = [
    request.operation,
    request.requestNonce,
    request.requestTimestamp,
    request.requestAudience,
    canonicalPayload(request.payload),
  ].join("\n");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signed = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signatureBase));
  return toHex(signed);
}

export function createServerProxyClient({
  baseUrl,
  session,
  sharedSecret,
  requestAudience = DEFAULT_AUDIENCE,
  fetchImpl = fetch,
  refreshSession = refreshServerSession,
  onSessionUpdated,
  nowFactory = () => new Date(),
  nonceFactory = randomNonce,
}: CreateServerProxyClientArgs) {
  const base = normalizeBaseUrl(baseUrl);

  const execute = async <TResult>(options: RequestOptions, allowRefresh: boolean): Promise<ProxyExecuteResult<TResult>> => {
    const accessToken = session.getAccessToken();
    if (!accessToken) {
      return {
        ok: false,
        status: 401,
        error: {
          status: 401,
          errorCode: "token_invalid",
          message: "missing access token",
          requestId: "server-proxy-client-auth",
          details: { reason: "no_access_token" },
        },
      };
    }

    if (!sharedSecret.trim()) {
      return {
        ok: false,
        status: 422,
        error: {
          status: 422,
          errorCode: "proxy_secret_missing",
          message: "proxy shared secret is required for delegated mode",
          requestId: "server-proxy-client-secret",
          details: { operation: options.operation },
        },
      };
    }

    const requestBody: ProxyExecuteRequest = {
      operation: options.operation,
      payload: options.payload,
      requestNonce: nonceFactory(),
      requestTimestamp: nowFactory().toISOString(),
      requestAudience,
    };

    let signature: string;
    try {
      signature = await buildProxySignature(sharedSecret, requestBody);
    } catch (error) {
      return {
        ok: false,
        status: 500,
        error: {
          status: 500,
          errorCode: "proxy_signature_generation_failed",
          message: "failed to generate delegated request signature",
          requestId: "server-proxy-client-signature",
          details: { reason: String(error), operation: options.operation },
        },
      };
    }

    const endpoint = `${base}/api/proxy/execute`;

    let response: Response;
    try {
      response = await fetchImpl(endpoint, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
          "X-Proxy-Signature": signature,
        },
        body: JSON.stringify(requestBody),
      });
    } catch (error) {
      return {
        ok: false,
        status: 503,
        error: {
          status: 503,
          errorCode: "server_unreachable",
          message: "server proxy request failed",
          requestId: "server-proxy-client-network",
          details: { reason: String(error), operation: options.operation },
        },
      };
    }

    const payload = await safeJson(response);

    if (response.status === 401 && allowRefresh) {
      const refreshed = await refreshSession({ baseUrl: base, session, fetchImpl });
      if (!refreshed.ok) {
        return { ok: false, status: refreshed.error.status, error: refreshed.error };
      }
      session.setTokens(refreshed.tokens);
      onSessionUpdated?.(refreshed.tokens);
      return execute<TResult>(options, false);
    }

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: buildError(response.status, payload, "proxy_request_failed", "server proxy request failed", "server-proxy-client"),
      };
    }

    const objectPayload = asObject(payload);
    const requestId = objectPayload.requestId;
    const scope = objectPayload.scope;
    const operation = objectPayload.operation;
    if (
      typeof requestId !== "string"
      || typeof scope !== "string"
      || typeof operation !== "string"
      || !Object.prototype.hasOwnProperty.call(objectPayload, "result")
    ) {
      return {
        ok: false,
        status: 502,
        error: {
          status: 502,
          errorCode: "proxy_contract_invalid",
          message: "server proxy response contract invalid",
          requestId: "server-proxy-client-contract",
          details: objectPayload,
        },
      };
    }

    return {
      ok: true,
      status: response.status,
      data: {
        requestId,
        operation: operation as ProxyOperationType,
        scope,
        result: objectPayload.result as TResult,
      },
    };
  };

  return {
    execute<TResult>(operation: ProxyOperationType, payload: Record<string, unknown> = {}) {
      return execute<TResult>({ operation, payload }, true);
    },
  };
}
