import { describe, expect, it, vi } from "vitest";
import { createServerAnalysisClient } from "./serverAnalysisClient";
import { createServerSession } from "./serverAuthSession";

describe("serverAnalysisClient", () => {
  it("retries once after token 401 using refresh flow", async () => {
    const session = createServerSession({
      accessToken: "old-access",
      refreshToken: "refresh-token",
      accessExpiresAt: "2026-03-21T10:00:00Z",
      refreshExpiresAt: "2026-03-21T12:00:00Z",
      role: "analyst",
    });

    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({
          status: 401,
          errorCode: "token_expired",
          message: "expired",
          requestId: "req-1",
        }), { status: 401 }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({
          items: [],
          nextCursor: null,
          count: 0,
        }), { status: 200 }),
      );

    const refreshMock = vi.fn().mockImplementation(async () => {
      session.setTokens({
        accessToken: "new-access",
        refreshToken: "new-refresh",
        accessExpiresAt: "2026-03-21T13:00:00Z",
        refreshExpiresAt: "2026-03-21T15:00:00Z",
        role: "analyst",
      });
      return {
        ok: true as const,
        tokens: session.getTokens()!,
      };
    });

    const client = createServerAnalysisClient({
      baseUrl: "https://history.local:9000",
      session,
      fetchImpl: fetchMock,
      refreshSession: refreshMock,
    });

    const result = await client.getEvents({
      startAt: "2026-03-21T09:00:00Z",
      endAt: "2026-03-21T10:00:00Z",
      sourceType: "firewall",
      limit: 50,
    });

    expect(result.ok).toBe(true);
    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("returns refresh error when retry cannot renew session", async () => {
    const session = createServerSession({
      accessToken: "old-access",
      refreshToken: "refresh-token",
      accessExpiresAt: "2026-03-21T10:00:00Z",
      refreshExpiresAt: "2026-03-21T12:00:00Z",
      role: "analyst",
    });

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({
        status: 401,
        errorCode: "token_expired",
        message: "expired",
        requestId: "req-2",
      }), { status: 401 }),
    );

    const refreshMock = vi.fn().mockResolvedValue({
      ok: false,
      error: {
        status: 401,
        errorCode: "token_invalid",
        message: "invalid refresh token",
        requestId: "refresh-fail",
      },
    });

    const client = createServerAnalysisClient({
      baseUrl: "https://history.local:9000",
      session,
      fetchImpl: fetchMock,
      refreshSession: refreshMock,
    });

    const result = await client.getFreshness();

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("Expected error result");
    }
    expect(result.error.errorCode).toBe("token_invalid");
    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("builds trends endpoint query string with expected params", async () => {
    const session = createServerSession({
      accessToken: "access",
      refreshToken: "refresh",
      accessExpiresAt: "2026-03-21T13:00:00Z",
      refreshExpiresAt: "2026-03-21T15:00:00Z",
      role: "analyst",
    });

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({
        items: [],
        count: 0,
      }), { status: 200 }),
    );

    const client = createServerAnalysisClient({
      baseUrl: "https://history.local:9000",
      session,
      fetchImpl: fetchMock,
    });

    await client.getTrends({
      startAt: "2026-03-20T00:00:00Z",
      endAt: "2026-03-21T00:00:00Z",
      sourceType: "dhcp",
      bucketGrain: "coarse",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toContain("/api/history/trends");
    expect(url).toContain("sourceType=dhcp");
    expect(url).toContain("bucketGrain=coarse");
  });
});
