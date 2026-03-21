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
    expect(decision.intervalMs).toBeLessThanOrEqual(60_000 * 4);
    expect(decision.backoffCeilingMs).toBeGreaterThan(60_000 * 3);
    expect(decision.loadMode).toBe("degraded");
    expect(decision.reasons).toEqual(
      expect.arrayContaining(["source-stale", "backlog-high", "retry-escalation"]),
    );
  });

  it("returns degraded mode with source-error reason when source health is error", () => {
    const decision = resolveAdaptivePollPolicy({
      source: "firewall-stream",
      baseIntervalMs: 30_000,
      healthStatus: "error",
      backlogSize: 50,
      retryAttempt: 1,
    });

    expect(decision.source).toBe("firewall-stream");
    expect(decision.loadMode).toBe("degraded");
    expect(decision.reasons).toContain("source-error");
    expect(decision.intervalMs).toBeGreaterThan(30_000);
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
