import { describe, expect, it } from "vitest";
import { mapServerFreshnessToSourceHealth, toServerAnalysisModeBadge } from "./serverFreshnessMapper";

describe("serverFreshnessMapper", () => {
  it("maps healthy freshness payload into server-api and per-source cards", () => {
    const cards = mapServerFreshnessToSourceHealth({
      status: 200,
      data: {
        generatedAt: "2026-03-21T12:00:00.000Z",
        overallSeverity: "Info",
        sources: [
          {
            sourceKey: "firewall",
            state: "Healthy",
            lagSeconds: 5,
            checkpointCursor: "fw-1",
            severityCandidate: "Info",
            fallbackRecommended: false,
            confidenceImpact: "low",
          },
        ],
        fallbackGuidance: {
          recommended: false,
          reason: "No fallback needed",
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
    }, { nowMillis: Date.parse("2026-03-21T12:01:00.000Z") });

    expect(cards[0]?.key).toBe("server-api");
    expect(cards[0]?.status).toBe("healthy");
    expect(cards.some((card) => card.key === "firewall")).toBe(true);
  });

  it("marks server-api as stale when generatedAt exceeds stale threshold", () => {
    const cards = mapServerFreshnessToSourceHealth({
      status: 200,
      data: {
        generatedAt: "2026-03-21T12:00:00.000Z",
        overallSeverity: "Warn",
        sources: [],
        fallbackGuidance: {
          recommended: true,
          reason: "Source stale",
          actionLabel: "Switch to local",
          actionKey: "switch-local",
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
    }, { nowMillis: Date.parse("2026-03-21T12:10:00.000Z") });

    expect(cards[0]?.status).toBe("stale");
  });

  it("maps auth or connectivity failures to server-api error card", () => {
    const cards = mapServerFreshnessToSourceHealth(null, {
      errorMessage: "token_invalid: missing token",
    });

    expect(cards).toHaveLength(1);
    expect(cards[0]?.status).toBe("error");
    expect(cards[0]?.detail).toContain("token_invalid");
  });

  it("returns stable mode badges for server, fallback, and local-only modes", () => {
    expect(toServerAnalysisModeBadge("server")).toEqual({
      mode: "server",
      label: "Server-first",
      tone: "healthy",
    });
    expect(toServerAnalysisModeBadge("fallback-local")).toEqual({
      mode: "fallback-local",
      label: "Fallback local",
      tone: "warning",
    });
    expect(toServerAnalysisModeBadge("local-only")).toEqual({
      mode: "local-only",
      label: "Local only",
      tone: "muted",
    });
  });
});
