import { describe, expect, it, vi } from "vitest";
import { runWithInFlightGuard } from "./webfilterInFlightGuard.ts";

describe("runWithInFlightGuard", () => {
  it("coalesces auto-refresh and manual refresh triggers while fetch is in flight", async () => {
    const inFlightRef: { current: Promise<string> | null } = { current: null };
    const pending = new Promise<string>(() => undefined);
    const fetchLogs = vi.fn(() => pending);

    const autoRefreshPromise = runWithInFlightGuard(inFlightRef, fetchLogs);
    const manualRefreshPromise = runWithInFlightGuard(inFlightRef, fetchLogs);

    expect(fetchLogs).toHaveBeenCalledTimes(1);
    expect(manualRefreshPromise).toBe(autoRefreshPromise);
    expect(inFlightRef.current).not.toBeNull();
  });

  it("coalesces schedule-refetch trigger while a previous fetch is still running", async () => {
    const inFlightRef: { current: Promise<number> | null } = { current: null };
    const pending = new Promise<number>(() => undefined);
    const fetchLogs = vi.fn(() => pending);

    const first = runWithInFlightGuard(inFlightRef, fetchLogs);
    const scheduledRefetch = runWithInFlightGuard(inFlightRef, fetchLogs);

    expect(fetchLogs).toHaveBeenCalledTimes(1);
    expect(scheduledRefetch).toBe(first);
    expect(inFlightRef.current).not.toBeNull();
  });

  it("starts a new fetch after the previous in-flight request settles", async () => {
    const inFlightRef: { current: Promise<string> | null } = { current: null };
    const fetchLogs = vi
      .fn<() => Promise<string>>()
      .mockResolvedValueOnce("first")
      .mockResolvedValueOnce("second");

    await runWithInFlightGuard(inFlightRef, fetchLogs);
    await runWithInFlightGuard(inFlightRef, fetchLogs);

    expect(fetchLogs).toHaveBeenCalledTimes(2);
  });
});
