import { describe, expect, it } from "vitest";
import { resolveAdaptivePollPolicy } from "./adaptivePollingPolicy";

describe("adaptivePollingPolicy", () => {
  it("increases interval and backoff ceiling for stale or degraded conditions", () => {
    const decision = resolveAdaptivePollPolicy({
      source: "server-api",
      baseIntervalMs: 60_000,
      healthStatus: "stale",
      backlogSize: 600,
      retryAttempt: 4,
    });

    expect(decision.intervalMs).toBeGreaterThan(60_000);
    expect(decision.backoffCeilingMs).toBeGreaterThan(60_000 * 3);
    expect(decision.loadMode).toBe("degraded");
    expect(decision.reasons).toEqual(
      expect.arrayContaining(["source-stale", "backlog-high", "retry-escalation"]),
    );
  });

  it("keeps normal cadence for healthy low-backlog sources", () => {
    const decision = resolveAdaptivePollPolicy({
      source: "leases",
      baseIntervalMs: 120_000,
      healthStatus: "healthy",
      backlogSize: 20,
      retryAttempt: 0,
    });

    expect(decision.intervalMs).toBe(120_000);
    expect(decision.loadMode).toBe("normal");
    expect(decision.reasons).toEqual([]);
  });
});
