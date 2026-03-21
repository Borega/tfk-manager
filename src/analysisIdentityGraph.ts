export type AnalysisIdentityField = "ip" | "mac" | "hostname" | "user";

export type AnalysisIdentityConfidence = "high" | "medium" | "low";

export type AnalysisIdentitySource = "static-lease" | "dynamic-lease" | "firewall-log" | "webfilter-log";

export type AnalysisIdentityObservation = {
  sourceType: AnalysisIdentitySource;
  ip?: string;
  mac?: string;
  hostname?: string;
  user?: string;
  observedAt?: string;
};

export type AnalysisIdentityNode = {
  id: string;
  field: AnalysisIdentityField;
  value: string;
  displayValue: string;
};

export type AnalysisIdentityEvidenceRef = {
  sourceType: AnalysisIdentitySource;
  field: AnalysisIdentityField;
  value: string;
  observedAt?: string;
};

export type AnalysisIdentityLink = {
  id: string;
  fromNodeId: string;
  toNodeId: string;
  confidence: AnalysisIdentityConfidence;
  evidenceCount: number;
  evidence: AnalysisIdentityEvidenceRef[];
};

export type AnalysisIdentityGraph = {
  nodes: AnalysisIdentityNode[];
  links: AnalysisIdentityLink[];
};

const FIELD_ORDER: AnalysisIdentityField[] = ["ip", "mac", "hostname", "user"];

function normalizeIdentityValue(field: AnalysisIdentityField, raw: string | undefined): string {
  const value = (raw ?? "").trim();
  if (!value) return "";
  if (field === "ip") return value;
  if (field === "mac") return value.toLowerCase();
  return value.toLowerCase();
}

function toNodeId(field: AnalysisIdentityField, normalizedValue: string): string {
  return `${field}:${normalizedValue}`;
}

function toConfidence(evidenceCount: number, sourceCount: number): AnalysisIdentityConfidence {
  if (evidenceCount >= 4 && sourceCount >= 2) return "high";
  if (evidenceCount >= 2) return "medium";
  return "low";
}

function compareFieldOrder(a: AnalysisIdentityField, b: AnalysisIdentityField): number {
  return FIELD_ORDER.indexOf(a) - FIELD_ORDER.indexOf(b);
}

function toObservationEntries(observation: AnalysisIdentityObservation): Array<{ field: AnalysisIdentityField; normalized: string; displayValue: string }> {
  const fields: AnalysisIdentityField[] = ["ip", "mac", "hostname", "user"];
  const entries: Array<{ field: AnalysisIdentityField; normalized: string; displayValue: string }> = [];
  for (const field of fields) {
    const rawValue = observation[field];
    const normalized = normalizeIdentityValue(field, rawValue);
    if (!normalized) continue;
    entries.push({
      field,
      normalized,
      displayValue: (rawValue ?? "").trim(),
    });
  }
  return entries;
}

export function buildAnalysisIdentityGraph(observations: AnalysisIdentityObservation[]): AnalysisIdentityGraph {
  const nodeMap = new Map<string, AnalysisIdentityNode>();
  const linkEvidence = new Map<string, Map<string, AnalysisIdentityEvidenceRef>>();

  for (const observation of observations) {
    const entries = toObservationEntries(observation);
    for (const entry of entries) {
      const nodeId = toNodeId(entry.field, entry.normalized);
      if (!nodeMap.has(nodeId)) {
        nodeMap.set(nodeId, {
          id: nodeId,
          field: entry.field,
          value: entry.normalized,
          displayValue: entry.displayValue,
        });
      }
    }

    for (let i = 0; i < entries.length; i += 1) {
      for (let j = i + 1; j < entries.length; j += 1) {
        const leftNodeId = toNodeId(entries[i].field, entries[i].normalized);
        const rightNodeId = toNodeId(entries[j].field, entries[j].normalized);
        const [fromNodeId, toNodeIdStable] = [leftNodeId, rightNodeId].sort();
        const linkId = `${fromNodeId}<->${toNodeIdStable}`;

        const evidenceRefs: AnalysisIdentityEvidenceRef[] = [entries[i], entries[j]].map((entry) => ({
          sourceType: observation.sourceType,
          field: entry.field,
          value: entry.normalized,
          observedAt: (observation.observedAt ?? "").trim() || undefined,
        }));

        const existingEvidence = linkEvidence.get(linkId) ?? new Map<string, AnalysisIdentityEvidenceRef>();
        for (const evidence of evidenceRefs) {
          const evidenceKey = [evidence.sourceType, evidence.field, evidence.value, evidence.observedAt ?? ""].join("|");
          existingEvidence.set(evidenceKey, evidence);
        }
        linkEvidence.set(linkId, existingEvidence);
      }
    }
  }

  const nodes = Array.from(nodeMap.values()).sort((a, b) => {
    const fieldOrderDiff = compareFieldOrder(a.field, b.field);
    if (fieldOrderDiff !== 0) return fieldOrderDiff;
    if (a.value !== b.value) return a.value.localeCompare(b.value);
    return a.id.localeCompare(b.id);
  });

  const links = Array.from(linkEvidence.entries())
    .map(([id, evidenceMap]) => {
      const [fromNodeId, toNodeIdStable] = id.split("<->");
      const evidence = Array.from(evidenceMap.values()).sort((a, b) => {
        if (a.sourceType !== b.sourceType) return a.sourceType.localeCompare(b.sourceType);
        const fieldOrderDiff = compareFieldOrder(a.field, b.field);
        if (fieldOrderDiff !== 0) return fieldOrderDiff;
        if (a.value !== b.value) return a.value.localeCompare(b.value);
        return (a.observedAt ?? "").localeCompare(b.observedAt ?? "");
      });
      const evidenceCount = evidence.length;
      const sourceCount = new Set(evidence.map((item) => item.sourceType)).size;
      return {
        id,
        fromNodeId,
        toNodeId: toNodeIdStable,
        confidence: toConfidence(evidenceCount, sourceCount),
        evidenceCount,
        evidence,
      } satisfies AnalysisIdentityLink;
    })
    .sort((a, b) => a.id.localeCompare(b.id));

  return {
    nodes,
    links,
  };
}
