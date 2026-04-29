export const SERVER_SOURCE_TYPES = ["dhcp", "firewall", "webfilter"] as const;
export type ServerSourceType = (typeof SERVER_SOURCE_TYPES)[number];

export const SERVER_BUCKET_GRAINS = ["fine", "coarse"] as const;
export type ServerBucketGrain = (typeof SERVER_BUCKET_GRAINS)[number];

export type ServerApiErrorEnvelope = {
  status: number;
  errorCode: string;
  message: string;
  requestId: string;
  details?: Record<string, unknown> | null;
};

export type ServerEventsQuery = {
  startAt: string;
  endAt: string;
  sourceType?: ServerSourceType;
  cursor?: string;
  limit?: number;
};

export type ServerTrendsQuery = {
  startAt: string;
  endAt: string;
  sourceType?: ServerSourceType;
  bucketGrain?: ServerBucketGrain;
};

export type ServerEventItem = {
  eventId: string;
  sourceType: ServerSourceType;
  sourceEntityId: string;
  occurredAt: string;
  observedAt: string;
  payloadHash: string;
  lineageVersion: number;
  confidenceState: string;
  rawPayloadJson: string;
};

export type ServerEventsResponse = {
  items: ServerEventItem[];
  nextCursor: string | null;
  count: number;
};

export type ServerTrendBucket = {
  bucketStart: string;
  bucketGrain: ServerBucketGrain;
  sourceType: ServerSourceType;
  eventCount: number;
  updatedAt: string;
};

export type ServerTrendsResponse = {
  items: ServerTrendBucket[];
  count: number;
};

export type ServerPlotlyFigure = {
  data: Array<Record<string, unknown>>;
  layout: Record<string, unknown>;
  config?: Record<string, unknown>;
};

export type ServerAnalysisDashboardQuery = {
  startAt: string;
  endAt: string;
  bucketGrain?: ServerBucketGrain;
};

export type ServerAnalysisDashboardResponse = {
  generatedAt: string;
  window: {
    startAt: string;
    endAt: string;
    bucketGrain: ServerBucketGrain;
    eventCount: number;
  };
  trends: {
    dhcpLeaseCounts: Array<{ bucketStart: string; eventCount: number }>;
    firewallDenyCounts: Array<{ bucketStart: string; eventCount: number }>;
  };
  networkInfrastructure: {
    vlanIpPoolUtilization: Array<{
      vlan: string;
      activeDevices: number;
      poolCapacity: number;
      poolUsedPercent: number;
    }>;
    networkLoad: Array<{
      vlan: string;
      activeDevices: number;
      firewallDenies: number;
      blockedRequests: number;
      loadScore: number;
    }>;
    gruenPeakRecorded?: number;
  };
  deviceBehavior: {
    churn: {
      newDevices: number;
      departedDevices: number;
      stableDevices: number;
      churnRatePercent: number;
    };
    deviceTypes: Array<{ vendor: string; count: number }>;
    vlanTransitions: Array<{
      entityId: string;
      transitionCount: number;
      lastVlan: string;
      lastOccurredAt: string;
    }>;
    leaseDurationDistribution: Array<{ bucket: string; count: number }>;
    perDevice: Array<Record<string, unknown>>;
    perBlockedUrl: Array<{ url: string; blockCount: number }>;
  };
  securityPolicy: {
    firewallDeniesByVlan: Array<{ vlan: string; count: number }>;
    blockedCategories: Array<{ category: string; count: number }>;
    anomalousEvents: Array<Record<string, unknown>>;
    misconfigurations: Array<Record<string, unknown>>;
    topBlockedDomainsByVlan: Array<{ vlan: string; url: string; blockCount: number }>;
  };
  suggestions: string[];
  dashboards: {
    dhcpLeaseTimeseries: ServerPlotlyFigure;
    firewallDenyTimeseries: ServerPlotlyFigure;
    topBlockedDomainsByVlan: ServerPlotlyFigure;
    deviceChurnSummary: ServerPlotlyFigure;
  };
};

export type ServerFreshnessSource = {
  sourceKey: string;
  state: "Healthy" | "Degraded" | "Stale" | "Unknown";
  lagSeconds: number | null;
  checkpointCursor: string | null;
  severityCandidate: string;
  fallbackRecommended: boolean;
  confidenceImpact: string;
};

export type ServerFallbackGuidance = {
  recommended: boolean;
  reason: string;
  actionLabel: string;
  actionKey: string;
};

export type ServerRetentionLifecycle = {
  lastRunAt: string | null;
  cutoffAt: string | null;
  deletedCount: number;
  affectedWindows: string[];
  runStatus: string;
  nextScheduledAt: string | null;
};

export type ServerFreshnessData = {
  generatedAt: string;
  overallSeverity: string;
  sources: ServerFreshnessSource[];
  fallbackGuidance: ServerFallbackGuidance;
  retentionLifecycle: ServerRetentionLifecycle;
};

export type ServerFreshnessResponse = {
  status: number;
  data: ServerFreshnessData;
};

export type ServerClientResult<T> =
  | {
      ok: true;
      status: number;
      data: T;
    }
  | {
      ok: false;
      status: number;
      error: ServerApiErrorEnvelope;
    };

export function isServerApiErrorEnvelope(value: unknown): value is ServerApiErrorEnvelope {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ServerApiErrorEnvelope>;
  return (
    typeof candidate.status === "number"
    && typeof candidate.errorCode === "string"
    && typeof candidate.message === "string"
    && typeof candidate.requestId === "string"
  );
}
