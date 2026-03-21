import { describe, expect, it, vi } from "vitest";
import { runServerFirstAnalysis } from "./serverFirstAnalysis";

describe("runServerFirstAnalysis", () => {
  it("returns server mode when freshness, trends, and events succeed", async () => {
    const client = {
      getFreshness: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        data: {
          status: 200,
          data: {
            generatedAt: "2026-03-21T10:00:00Z",
            overallSeverity: "Info",
            sources: [],
            fallbackGuidance: {
              recommended: false,
              reason: "none",
              actionLabel: "Continue Server Mode",
              actionKey: "none",
            },
            retentionLifecycle: {
              lastRunAt: null,
              cutoffAt: null,
              deletedCount: 0,
              affectedWindows: [],
              runStatus: "unknown",
              nextScheduledAt: null,
            },
          },
        },
      }),
      getTrends: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        data: {
          items: [
            {
              bucketStart: "2026-03-21T09:00:00Z",
              bucketGrain: "coarse",
              sourceType: "firewall",
              eventCount: 2,
              updatedAt: "2026-03-21T10:00:00Z",
            },
          ],
          count: 1,
        },
      }),
      getEvents: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        data: {
          items: [],
          nextCursor: null,
          count: 0,
        },
      }),
    };

    const result = await runServerFirstAnalysis({
      client,
      window: {
        startAt: "2026-03-21T09:00:00Z",
        endAt: "2026-03-21T10:00:00Z",
        sourceType: "firewall",
        bucketGrain: "coarse",
      },
    });

    expect(result.mode).toBe("server");
    if (result.mode !== "server") {
      throw new Error("Expected server mode");
    }
    expect(result.trends.items.length).toBe(1);
    expect(client.getFreshness).toHaveBeenCalledTimes(1);
    expect(client.getTrends).toHaveBeenCalledTimes(1);
    expect(client.getEvents).toHaveBeenCalledTimes(1);
  });

  it("falls back when server call returns auth error and runs local fallback callback", async () => {
    const onFallbackLocal = vi.fn();
    const client = {
      getFreshness: vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        error: {
          status: 401,
          errorCode: "token_invalid",
          message: "missing token",
          requestId: "freshness-auth",
        },
      }),
      getTrends: vi.fn(),
      getEvents: vi.fn(),
    };

    const result = await runServerFirstAnalysis({
      client,
      window: {
        startAt: "2026-03-21T09:00:00Z",
        endAt: "2026-03-21T10:00:00Z",
      },
      onFallbackLocal,
    });

    expect(result.mode).toBe("fallback-local");
    if (result.mode !== "fallback-local") {
      throw new Error("Expected fallback-local mode");
    }
    expect(result.stage).toBe("freshness");
    expect(result.errorCode).toBe("token_invalid");
    expect(onFallbackLocal).toHaveBeenCalledTimes(1);
    expect(client.getTrends).not.toHaveBeenCalled();
    expect(client.getEvents).not.toHaveBeenCalled();
  });

  it("falls back for thrown network errors without bubbling", async () => {
    const onFallbackLocal = vi.fn();
    const client = {
      getFreshness: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        data: {
          status: 200,
          data: {
            generatedAt: "2026-03-21T10:00:00Z",
            overallSeverity: "Info",
            sources: [],
            fallbackGuidance: {
              recommended: false,
              reason: "none",
              actionLabel: "Continue Server Mode",
              actionKey: "none",
            },
            retentionLifecycle: {
              lastRunAt: null,
              cutoffAt: null,
              deletedCount: 0,
              affectedWindows: [],
              runStatus: "unknown",
              nextScheduledAt: null,
            },
          },
        },
      }),
      getTrends: vi.fn().mockRejectedValue(new Error("network down")),
      getEvents: vi.fn(),
    };

    const result = await runServerFirstAnalysis({
      client,
      window: {
        startAt: "2026-03-21T09:00:00Z",
        endAt: "2026-03-21T10:00:00Z",
      },
      onFallbackLocal,
    });

    expect(result.mode).toBe("fallback-local");
    if (result.mode !== "fallback-local") {
      throw new Error("Expected fallback-local mode");
    }
    expect(result.stage).toBe("unexpected");
    expect(result.errorCode).toBe("server_first_unexpected_error");
    expect(result.reason).toContain("network down");
    expect(onFallbackLocal).toHaveBeenCalledTimes(1);
  });
});
