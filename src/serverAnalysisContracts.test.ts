import { describe, expect, it } from "vitest";
import {
  SERVER_BUCKET_GRAINS,
  SERVER_SOURCE_TYPES,
  isServerApiErrorEnvelope,
  type ServerApiErrorEnvelope,
  type ServerEventsQuery,
  type ServerFreshnessResponse,
} from "./serverAnalysisContracts";

describe("serverAnalysisContracts", () => {
  it("defines supported source and bucket constants", () => {
    expect(SERVER_SOURCE_TYPES).toEqual(["dhcp", "firewall", "webfilter"]);
    expect(SERVER_BUCKET_GRAINS).toEqual(["fine", "coarse"]);
  });

  it("keeps events query and freshness envelope keys stable", () => {
    const query: ServerEventsQuery = {
      startAt: "2026-03-21T10:00:00Z",
      endAt: "2026-03-21T11:00:00Z",
      sourceType: "firewall",
      cursor: "evt-10",
      limit: 100,
    };

    const response: ServerFreshnessResponse = {
      status: 200,
      data: {
        generatedAt: "2026-03-21T11:00:00Z",
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
    };

    expect(query.startAt).toContain("T");
    expect(response.data).toHaveProperty("overallSeverity");
    expect(response.data).toHaveProperty("retentionLifecycle");
  });

  it("validates machine-readable error envelope shape", () => {
    const envelope: ServerApiErrorEnvelope = {
      status: 401,
      errorCode: "token_invalid",
      message: "missing or invalid token",
      requestId: "freshness-auth",
      details: { reason: "missing_subject_claim" },
    };

    expect(isServerApiErrorEnvelope(envelope)).toBe(true);
    expect(isServerApiErrorEnvelope({ status: 500, message: "x" })).toBe(false);
  });
});
