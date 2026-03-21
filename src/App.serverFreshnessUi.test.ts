import { describe, expect, it } from "vitest";
import appSource from "./App.tsx?raw";

describe("App server freshness UI wiring", () => {
  it("maps server freshness payload and renders mode banner state", () => {
    expect(appSource).toContain("mapServerFreshnessToSourceHealth");
    expect(appSource).toContain("analysisSourceHealthCards");
    expect(appSource).toContain("analysis-mode-banner");
    expect(appSource).not.toContain("Analysis mode:");
    expect(appSource).toContain("Fallback reason:");
  });

  it("wires server trend range controls and refresh action", () => {
    expect(appSource).toContain("Server Trend Window");
    expect(appSource).toContain("setServerTrendRange(Number(event.target.value))");
    expect(appSource).toContain("onClick={() => void refreshServerFirstAnalysisWindow()}");
    expect(appSource).toContain("Refresh server trend window");
    expect(appSource).toContain("source-health-grid");

    const sourceHealthGridMatches = appSource.match(/className=\"source-health-grid\"/g) ?? [];
    expect(sourceHealthGridMatches).toHaveLength(1);
  });
});
