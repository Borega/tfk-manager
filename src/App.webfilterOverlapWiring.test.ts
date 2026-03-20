import { describe, expect, it } from "vitest";
import appSource from "./App.tsx?raw";

describe("App webfilter overlap wiring", () => {
  it("routes webfilter log fetches through the in-flight guard", () => {
    expect(appSource).toContain("const wfLogsInFlightRef = useRef<Promise<WebfilterFetchResult> | null>(null);");
    expect(appSource).toContain("return runWithInFlightGuard(wfLogsInFlightRef, async () => {");
    expect(appSource).toContain("void handleFetchWfLogs();");
  });
});