import { describe, expect, it } from "vitest";
import { toWebfilterDynamicEnvelope } from "./webfilterDynamicProtocol";

describe("toWebfilterDynamicEnvelope", () => {
  it("maps success payload to state patch", () => {
    const envelope = toWebfilterDynamicEnvelope({
      ok: true,
      entries: [{ action: "allow", ip: "10.0.0.5" }],
      diag: "diag-text",
    }, new Date("2026-03-16T08:00:00.000Z"));

    expect(envelope.statePatch.entries?.length).toBe(1);
    expect(envelope.statePatch.error).toBeNull();
    expect(envelope.statePatch.diag).toBe("diag-text");
    expect(envelope.statePatch.lastRefreshIso).toBe("2026-03-16T08:00:00.000Z");
    expect(envelope.warnings.length).toBe(0);
  });

  it("maps legacy timer and parameter keys to typed actions", () => {
    const envelope = toWebfilterDynamicEnvelope({
      ok: false,
      error: "failed",
      timer: 1200,
      parameter: { autoRefresh: true, filter: "block" },
    });

    expect(envelope.actions).toContainEqual({ type: "schedule-refetch", delayMs: 5000 });
    expect(envelope.actions).toContainEqual({ type: "set-auto-refresh", enabled: true });
    expect(envelope.actions).toContainEqual({ type: "set-filter", filter: "block" });
  });

  it("warns and ignores unsupported source", () => {
    const envelope = toWebfilterDynamicEnvelope({
      ok: false,
      error: "no login",
      source: "opnsense-api",
    });

    expect(envelope.source).toBe("webfilter-ui");
    expect(envelope.warnings.some((item) => item.code === "unsupported-source")).toBe(true);
  });

  it("warns on unsupported actions", () => {
    const envelope = toWebfilterDynamicEnvelope({
      ok: false,
      error: "x",
      actions: [{ type: "unsupported-action" }],
    });

    expect(envelope.actions.length).toBe(0);
    expect(envelope.warnings.some((item) => item.code === "unsupported-action")).toBe(true);
  });
});
