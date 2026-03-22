import { describe, expect, it, vi } from "vitest";
import {
  canMutateViaServerProxy,
  createServerSession,
  loginServerSession,
  refreshServerSession,
} from "./serverAuthSession";

describe("serverAuthSession", () => {
  it("stores and clears tokens in session state", () => {
    const session = createServerSession();
    expect(session.getTokens()).toBeNull();

    session.setTokens({
      accessToken: "access-a",
      refreshToken: "refresh-a",
      accessExpiresAt: "2026-03-21T13:00:00Z",
      refreshExpiresAt: "2026-03-21T14:00:00Z",
      role: "analyst",
    });

    expect(session.getAccessToken()).toBe("access-a");
    expect(session.getRefreshToken()).toBe("refresh-a");
    expect(session.isAccessTokenExpired(Date.parse("2026-03-21T12:59:00Z"))).toBe(false);

    session.clear();
    expect(session.getTokens()).toBeNull();
  });

  it("refreshes and updates tokens on successful refresh response", async () => {
    const session = createServerSession({
      accessToken: "old-access",
      refreshToken: "old-refresh",
      accessExpiresAt: "2026-03-21T12:00:00Z",
      refreshExpiresAt: "2026-03-21T13:00:00Z",
      role: "analyst",
    });

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({
        accessToken: "new-access",
        refreshToken: "new-refresh",
        accessExpiresAt: "2026-03-21T14:00:00Z",
        refreshExpiresAt: "2026-03-21T15:00:00Z",
      }), { status: 200 }),
    );

    const result = await refreshServerSession({
      baseUrl: "https://example.local:8080/",
      session,
      fetchImpl: fetchMock,
    });

    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://example.local:8080/api/auth/refresh");
    expect(session.getTokens()?.accessToken).toBe("new-access");
    expect(session.getTokens()?.refreshToken).toBe("new-refresh");
  });

  it("returns a normalized error when refresh request fails", async () => {
    const session = createServerSession({
      accessToken: "old-access",
      refreshToken: "old-refresh",
      accessExpiresAt: "2026-03-21T12:00:00Z",
      refreshExpiresAt: "2026-03-21T13:00:00Z",
      role: "analyst",
    });

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({
        status: 401,
        errorCode: "token_invalid",
        message: "invalid refresh token",
        requestId: "refresh-auth",
      }), { status: 401 }),
    );

    const result = await refreshServerSession({
      baseUrl: "https://example.local:8080",
      session,
      fetchImpl: fetchMock,
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("Expected refresh result to be an error");
    }
    expect(result.error.status).toBe(401);
    expect(result.error.errorCode).toBe("token_invalid");
  });

  it("logs in and stores server session tokens", async () => {
    const session = createServerSession();
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({
        accessToken: "login-access",
        refreshToken: "login-refresh",
        accessExpiresAt: "2026-03-21T14:00:00Z",
        refreshExpiresAt: "2026-03-21T15:00:00Z",
        role: "admin",
      }), { status: 200 }),
    );

    const result = await loginServerSession({
      baseUrl: "https://example.local:8080/",
      username: "admin",
      password: "secret",
      session,
      fetchImpl: fetchMock,
    });

    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://example.local:8080/api/auth/login");
    expect(session.getTokens()?.accessToken).toBe("login-access");
    expect(session.getTokens()?.refreshToken).toBe("login-refresh");
    expect(session.getTokens()?.role).toBe("admin");
  });

  it("allows mutating proxy operations only for admin role", () => {
    const analystSession = createServerSession({
      accessToken: "analyst-token",
      refreshToken: "analyst-refresh",
      accessExpiresAt: "2026-03-21T14:00:00Z",
      refreshExpiresAt: "2026-03-21T15:00:00Z",
      role: "analyst",
    });
    const adminSession = createServerSession({
      accessToken: "admin-token",
      refreshToken: "admin-refresh",
      accessExpiresAt: "2026-03-21T14:00:00Z",
      refreshExpiresAt: "2026-03-21T15:00:00Z",
      role: "admin",
    });

    expect(canMutateViaServerProxy(analystSession)).toBe(false);
    expect(canMutateViaServerProxy(adminSession)).toBe(true);
  });
});
