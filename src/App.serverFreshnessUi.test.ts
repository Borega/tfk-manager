import { describe, expect, it } from "vitest";
import appSource from "./App.tsx?raw";

describe("App server freshness UI wiring", () => {
  it("maps server freshness payload and renders mode banner state", () => {
    expect(appSource).toContain("mapServerFreshnessToSourceHealth");
    expect(appSource).toContain("analysis-mode-banner");
    expect(appSource).toContain("Analysis mode:");
    expect(appSource).toContain("Fallback reason:");
  });

  it("wires server trend range controls and refresh action", () => {
    expect(appSource).toContain("Server Trend Window");
    expect(appSource).toContain("setServerTrendRange(Number(event.target.value))");
    expect(appSource).toContain("Refresh server trend window");
    expect(appSource).toContain("source-health-grid");
  });
});
