import { describe, expect, it } from "vitest";
import {
  applyPollJitterMs,
  formatRetryWaitSeconds,
  getWebfilterPollIntervalMs,
  isRetryReady,
  nextRetryDelayMs,
} from "./sourcePollingPolicy";

describe("sourcePollingPolicy", () => {
  it("grows retry delay exponentially and clamps by source max", () => {
    expect(nextRetryDelayMs("webfilter-ui", 0)).toBe(8000);
    expect(nextRetryDelayMs("webfilter-ui", 1)).toBe(16000);
    expect(nextRetryDelayMs("webfilter-ui", 10)).toBe(120000);
  });

  it("marks retry ready when no retry timestamp exists", () => {
    expect(isRetryReady(null, Date.now())).toBe(true);
  });

  it("marks retry not ready before target time and ready after", () => {
    const base = Date.parse("2026-03-16T09:30:00.000Z");
    const next = new Date(base + 5000).toISOString();
    expect(isRetryReady(next, base)).toBe(false);
    expect(isRetryReady(next, base + 5000)).toBe(true);
  });

  it("returns remaining retry wait in whole seconds", () => {
    const base = Date.parse("2026-03-16T09:30:00.000Z");
    const next = new Date(base + 4500).toISOString();
    expect(formatRetryWaitSeconds(next, base)).toBe(5);
    expect(formatRetryWaitSeconds(next, base + 4500)).toBe(0);
  });

  it("uses faster interval in visible interactive view", () => {
    expect(
      getWebfilterPollIntervalMs({
        isInteractiveView: true,
        isDocumentVisible: true,
        hasRecentError: false,
      }),
    ).toBe(3000);
  });

  it("falls back to safer visible interval after recent errors", () => {
    expect(
      getWebfilterPollIntervalMs({
        isInteractiveView: true,
        isDocumentVisible: true,
        hasRecentError: true,
      }),
    ).toBe(5000);
  });

  it("falls back to slower interval when hidden and non-interactive", () => {
    expect(
      getWebfilterPollIntervalMs({
        isInteractiveView: false,
        isDocumentVisible: false,
        hasRecentError: true,
      }),
    ).toBe(30000);
  });

  it("applies bounded jitter around the base value", () => {
    const low = applyPollJitterMs(5000, 0.1, () => 0);
    const high = applyPollJitterMs(5000, 0.1, () => 1);
    expect(low).toBe(4500);
    expect(high).toBe(5500);
  });
});
