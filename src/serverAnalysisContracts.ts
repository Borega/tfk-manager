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
