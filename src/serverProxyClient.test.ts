import { describe, expect, it, vi } from "vitest";
import { buildProxySignature, createServerProxyClient } from "./serverProxyClient";
import { createServerSession } from "./serverAuthSession";

describe("serverProxyClient", () => {
  it("sends signed delegated proxy requests", async () => {
    const session = createServerSession({
      accessToken: "token-a",
      refreshToken: "refresh-a",
      accessExpiresAt: "2026-03-21T12:00:00Z",
      refreshExpiresAt: "2026-03-21T13:00:00Z",
      role: "admin",
    });

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({
        requestId: "proxy-req-1",
        operation: "moveDynamicToStatic",
        scope: "proxy:dhcp:write",
        result: { ok: true, status: "success" },
      }), { status: 200 }),
    );

    const client = createServerProxyClient({
      baseUrl: "https://example.local:8080/",
      session,
      sharedSecret: "test-shared-secret",
      requestAudience: "tfk-manager-server",
      fetchImpl: fetchMock,
      nowFactory: () => new Date("2026-03-22T10:00:00.000Z"),
      nonceFactory: () => "0123456789abcdef0123456789abcdef",
    });

    const result = await client.execute<{ ok: boolean; status: string }>("moveDynamicToStatic", {
      iface: "Gruen",
      ip: "10.0.0.10",
      mac: "00:11:22:33:44:55",
      hostname: "lab-client",
    });

    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [endpoint, init] = fetchMock.mock.calls[0] ?? [];
    expect(endpoint).toBe("https://example.local:8080/api/proxy/execute");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer token-a");

    const body = JSON.parse(String(init?.body));
    const expectedSignature = await buildProxySignature("test-shared-secret", body);
    expect((init?.headers as Record<string, string>)["X-Proxy-Signature"]).toBe(expectedSignature);
  });

  it("refreshes server session and retries once after 401", async () => {
    const session = createServerSession({
      accessToken: "old-access",
      refreshToken: "refresh-a",
      accessExpiresAt: "2026-03-21T12:00:00Z",
      refreshExpiresAt: "2026-03-21T13:00:00Z",
      role: "admin",
    });

    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        status: 401,
        errorCode: "token_invalid",
        message: "expired",
        requestId: "proxy-auth",
      }), { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        requestId: "proxy-req-2",
        operation: "deleteStaticLease",
        scope: "proxy:dhcp:write",
        result: { ok: true, status: "success" },
      }), { status: 200 }));

    const refreshMock = vi.fn().mockResolvedValue({
      ok: true,
      tokens: {
        accessToken: "new-access",
        refreshToken: "refresh-a",
        accessExpiresAt: "2026-03-21T14:00:00Z",
        refreshExpiresAt: "2026-03-21T15:00:00Z",
        role: "admin",
      },
    });

    const client = createServerProxyClient({
      baseUrl: "https://example.local:8080",
      session,
      sharedSecret: "test-shared-secret",
      fetchImpl: fetchMock,
      refreshSession: refreshMock,
      nonceFactory: () => "abcdefabcdefabcdefabcdefabcdefab",
    });

    const result = await client.execute<{ ok: boolean; status: string }>("deleteStaticLease", {
      iface: "lan",
      mac: "00:11:22:33:44:55",
    });

    expect(result.ok).toBe(true);
    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [, secondInit] = fetchMock.mock.calls[1] ?? [];
    expect((secondInit?.headers as Record<string, string>).Authorization).toBe("Bearer new-access");
  });

  it("returns deterministic error when shared secret is missing", async () => {
    const session = createServerSession({
      accessToken: "token-a",
      refreshToken: "refresh-a",
      accessExpiresAt: "2026-03-21T12:00:00Z",
      refreshExpiresAt: "2026-03-21T13:00:00Z",
      role: "admin",
    });

    const fetchMock = vi.fn<typeof fetch>();
    const client = createServerProxyClient({
      baseUrl: "https://example.local:8080",
      session,
      sharedSecret: "",
      fetchImpl: fetchMock,
    });

    const result = await client.execute<{ ok: boolean }>("getDynamicLeases", {});

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("Expected missing-secret call to fail");
    }
    expect(result.error.errorCode).toBe("proxy_secret_missing");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
