import { describe, expect, it } from "vitest";
import appSource from "./App.tsx?raw";

describe("App server-first analysis wiring", () => {
  it("calls server-first orchestrator from analysis refresh path", () => {
    expect(appSource).toContain("runServerFirstAnalysis");
    expect(appSource).toContain("async function refreshServerFirstAnalysisWindow(): Promise<AnalysisMode>");
    expect(appSource).toContain("const mode = await refreshServerFirstAnalysisWindow();");
  });

  it("tracks fallback-local mode and preserves local refresh path", () => {
    expect(appSource).toContain("const [analysisMode, setAnalysisMode] = useState<AnalysisMode>(\"local-only\");");
    expect(appSource).toContain("setAnalysisMode(\"fallback-local\")");
    expect(appSource).toContain("await refreshLeasesSilently();");
  });
});
