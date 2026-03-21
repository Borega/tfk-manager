import { describe, expect, it } from "vitest";
import appSource from "./App.tsx?raw";

describe("App adaptive analytics wiring", () => {
  it("wires identity graph and explainable risk engines into analysis flow", () => {
    expect(appSource).toContain("buildAnalysisIdentityGraph");
    expect(appSource).toContain("computeExplainableRisk");
    expect(appSource).toContain("identityLinksByIp");
    expect(appSource).toContain("riskEvidenceByIp");
    expect(appSource).toContain("Identity Links");
    expect(appSource).toContain("Risk Evidence");
  });

  it("applies adaptive polling decisions in analysis refresh loops", () => {
    expect(appSource).toContain("resolveAdaptivePollPolicy");
    expect(appSource).toContain("const leasePoll = resolveAdaptivePollPolicy");
    expect(appSource).toContain("const serverPoll = resolveAdaptivePollPolicy");
    expect(appSource).toContain("const firewallPoll = resolveAdaptivePollPolicy");
    expect(appSource).toContain("const adaptivePoll = resolveAdaptivePollPolicy");
  });
});
