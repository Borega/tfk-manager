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

const RULE = {
  FW_BLOCK_ACTIVITY: "fw-block-activity",
  WF_BLOCK_ACTIVITY: "wf-block-activity",
  DUAL_BLOCK: "dual-block-overlap",
  UNKNOWN_SEGMENT: "unknown-segment-penalty",
  LOW_IDENTITY_WITH_BLOCK: "low-identity-block-penalty",
  BASELINE_NO_ACTIVITY: "baseline-no-activity",
} as const;

const WEIGHT = {
  FW_BLOCK_PER_EVENT: 6,
  WF_BLOCK_PER_EVENT: 4,
  DUAL_BLOCK: 8,
  UNKNOWN_SEGMENT: 8,
  LOW_IDENTITY_WITH_BLOCK: 2,
} as const;

function clampRiskScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function toSeverity(score: number): AnalysisRiskSeverity {
  if (score >= 40) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export function computeExplainableRisk(input: ExplainableRiskInput): ExplainableRiskResult {
  const fwBlock = Number.isFinite(input.fwBlock) ? Math.max(0, Math.floor(input.fwBlock)) : 0;
  const wfBlock = Number.isFinite(input.wfBlock) ? Math.max(0, Math.floor(input.wfBlock)) : 0;

  const evidence: AnalysisRiskEvidenceReference[] = [];
  let score = 0;

  if (fwBlock > 0) {
    const weight = fwBlock * WEIGHT.FW_BLOCK_PER_EVENT;
    score += weight;
    evidence.push({
      ruleId: RULE.FW_BLOCK_ACTIVITY,
      sourceType: "firewall",
      field: "fwBlock",
      observedValue: String(fwBlock),
      weight,
    });
  }

  if (wfBlock > 0) {
    const weight = wfBlock * WEIGHT.WF_BLOCK_PER_EVENT;
    score += weight;
    evidence.push({
      ruleId: RULE.WF_BLOCK_ACTIVITY,
      sourceType: "webfilter",
      field: "wfBlock",
      observedValue: String(wfBlock),
      weight,
    });
  }

  if (input.hasDualBlock) {
    score += WEIGHT.DUAL_BLOCK;
    evidence.push({
      ruleId: RULE.DUAL_BLOCK,
      sourceType: "analysis",
      field: "hasDualBlock",
      observedValue: "true",
      weight: WEIGHT.DUAL_BLOCK,
    });
  }

  if ((input.segment ?? "") === "Unknown") {
    score += WEIGHT.UNKNOWN_SEGMENT;
    evidence.push({
      ruleId: RULE.UNKNOWN_SEGMENT,
      sourceType: "classification",
      field: "segment",
      observedValue: "Unknown",
      weight: WEIGHT.UNKNOWN_SEGMENT,
    });
  }

  if (input.identityConfidence === "low" && (fwBlock > 0 || wfBlock > 0)) {
    score += WEIGHT.LOW_IDENTITY_WITH_BLOCK;
    evidence.push({
      ruleId: RULE.LOW_IDENTITY_WITH_BLOCK,
      sourceType: "identity",
      field: "identityConfidence",
      observedValue: "low",
      weight: WEIGHT.LOW_IDENTITY_WITH_BLOCK,
    });
  }

  if (evidence.length === 0) {
    return {
      score: 0,
      severity: "low",
      evidence: [
        {
          ruleId: RULE.BASELINE_NO_ACTIVITY,
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
  const orderedEvidence = [...evidence].sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight;
    if (a.ruleId !== b.ruleId) return a.ruleId.localeCompare(b.ruleId);
    if (a.sourceType !== b.sourceType) return a.sourceType.localeCompare(b.sourceType);
    return a.field.localeCompare(b.field);
  });

  return {
    score: clampedScore,
    severity: toSeverity(clampedScore),
    evidence: orderedEvidence,
    reason: "Risk derived from weighted blocking and identity context evidence.",
  };
}
