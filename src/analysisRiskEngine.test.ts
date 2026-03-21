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

  it("raises severity for dual-block with low identity confidence and includes evidence", () => {
    const result = computeExplainableRisk({
      fwBlock: 3,
      wfBlock: 2,
      hasDualBlock: true,
      identityConfidence: "low",
      segment: "Unknown",
    });

    expect(result.severity).toBe("high");
    expect(result.score).toBeGreaterThanOrEqual(40);
    expect(result.evidence.map((item) => item.ruleId)).toEqual(
      expect.arrayContaining([
        "fw-block-activity",
        "wf-block-activity",
        "dual-block-overlap",
        "low-identity-block-penalty",
      ]),
    );
  });

  it("lowers score when block activity is reduced while preserving evidence provenance", () => {
    const high = computeExplainableRisk({
      fwBlock: 4,
      wfBlock: 2,
      hasDualBlock: true,
      identityConfidence: "medium",
      segment: "Dynamic Gruen",
    });

    const reduced = computeExplainableRisk({
      fwBlock: 1,
      wfBlock: 0,
      hasDualBlock: false,
      identityConfidence: "medium",
      segment: "Dynamic Gruen",
    });

    expect(reduced.score).toBeLessThan(high.score);
    expect(high.evidence.length).toBeGreaterThan(reduced.evidence.length);
    for (const evidence of high.evidence) {
      expect(evidence.sourceType).toMatch(/firewall|webfilter|identity|classification|analysis/);
      expect(evidence.field.length).toBeGreaterThan(0);
      expect(evidence.ruleId.length).toBeGreaterThan(0);
    }
  });
});
