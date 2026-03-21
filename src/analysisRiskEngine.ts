export type AnalysisRiskSeverity = "low" | "medium" | "high";

export type AnalysisRiskSource = "firewall" | "webfilter" | "identity" | "classification" | "analysis";

export type AnalysisRiskEvidenceReference = {
  ruleId: string;
  sourceType: AnalysisRiskSource;
  field: string;
  observedValue: string;
  weight: number;
};

export type ExplainableRiskInput = {
  fwBlock: number;
  wfBlock: number;
  hasDualBlock?: boolean;
  identityConfidence?: "high" | "medium" | "low";
  segment?: string;
};

export type ExplainableRiskResult = {
  score: number;
  severity: AnalysisRiskSeverity;
  evidence: AnalysisRiskEvidenceReference[];
  reason: string;
};

function clampRiskScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function toSeverity(score: number): AnalysisRiskSeverity {
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export function computeExplainableRisk(input: ExplainableRiskInput): ExplainableRiskResult {
  const fwBlock = Number.isFinite(input.fwBlock) ? Math.max(0, Math.floor(input.fwBlock)) : 0;
  const wfBlock = Number.isFinite(input.wfBlock) ? Math.max(0, Math.floor(input.wfBlock)) : 0;

  const evidence: AnalysisRiskEvidenceReference[] = [];
  let score = 0;

  if (fwBlock > 0) {
    const weight = fwBlock * 6;
    score += weight;
    evidence.push({
      ruleId: "fw-block-activity",
      sourceType: "firewall",
      field: "fwBlock",
      observedValue: String(fwBlock),
      weight,
    });
  }

  if (wfBlock > 0) {
    const weight = wfBlock * 4;
    score += weight;
    evidence.push({
      ruleId: "wf-block-activity",
      sourceType: "webfilter",
      field: "wfBlock",
      observedValue: String(wfBlock),
      weight,
    });
  }

  if (evidence.length === 0) {
    return {
      score: 0,
      severity: "low",
      evidence: [
        {
          ruleId: "baseline-no-activity",
          sourceType: "analysis",
          field: "events",
          observedValue: "none",
          weight: 0,
        },
      ],
      reason: "No blocking evidence observed for this device.",
    };
  }

  const clampedScore = clampRiskScore(score);
  return {
    score: clampedScore,
    severity: toSeverity(clampedScore),
    evidence,
    reason: "Risk derived from observed blocking activity.",
  };
}
