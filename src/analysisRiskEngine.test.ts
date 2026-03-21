import { describe, expect, it } from "vitest";
import { computeExplainableRisk } from "./analysisRiskEngine";

describe("analysisRiskEngine", () => {
  it("returns score, severity, and evidence envelope", () => {
    const result = computeExplainableRisk({
      fwBlock: 3,
      wfBlock: 1,
      identityConfidence: "medium",
      hasDualBlock: false,
      segment: "Dynamic Gruen",
    });

    expect(result.score).toBeTypeOf("number");
    expect(result.severity).toMatch(/low|medium|high/);
    expect(Array.isArray(result.evidence)).toBe(true);
    expect(result.evidence[0]).toEqual(
      expect.objectContaining({
        ruleId: expect.any(String),
        sourceType: expect.any(String),
        field: expect.any(String),
        observedValue: expect.any(String),
      }),
    );
  });

  it("returns default low-risk output with explicit reason when no evidence exists", () => {
    const result = computeExplainableRisk({
      fwBlock: 0,
      wfBlock: 0,
      identityConfidence: "high",
      hasDualBlock: false,
      segment: "Static Gruen",
    });

    expect(result.score).toBe(0);
    expect(result.severity).toBe("low");
    expect(result.reason).toContain("No blocking evidence");
    expect(result.evidence).toEqual([
      expect.objectContaining({
        ruleId: "baseline-no-activity",
        weight: 0,
      }),
    ]);
  });
});
