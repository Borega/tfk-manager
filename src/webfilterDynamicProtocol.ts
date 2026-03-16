export type WebfilterUiFilter = "all" | "allow" | "block";

export type WebfilterDynamicAction =
  | { type: "set-filter"; filter: WebfilterUiFilter }
  | { type: "set-auto-refresh"; enabled: boolean }
  | { type: "schedule-refetch"; delayMs: number };

export type WebfilterDynamicWarning = {
  code: string;
  message: string;
};

export type WebfilterDynamicStatePatch<TEntry> = {
  entries?: TEntry[];
  error?: string | null;
  diag?: string | null;
  lastRefreshIso?: string;
  lastRefreshLabel?: string;
};

export type WebfilterDynamicEnvelope<TEntry> = {
  source: "webfilter-ui";
  statePatch: WebfilterDynamicStatePatch<TEntry>;
  actions: WebfilterDynamicAction[];
  warnings: WebfilterDynamicWarning[];
};

type IncomingDynamicAction =
  | { type?: string; filter?: string; enabled?: boolean; delayMs?: number }
  | null
  | undefined;

type IncomingWebfilterResult<TEntry> = {
  ok: boolean;
  entries?: TEntry[];
  error?: string;
  diag?: string;
  source?: string;
  actions?: IncomingDynamicAction[];
  warnings?: Array<{ code?: string; message?: string }>;
  timer?: number;
  parameter?: {
    autoRefresh?: boolean;
    filter?: string;
  };
};

function clampRefetchDelay(delayMs: number): number {
  if (!Number.isFinite(delayMs)) return 30_000;
  if (delayMs < 5_000) return 5_000;
  if (delayMs > 5 * 60_000) return 5 * 60_000;
  return Math.round(delayMs);
}

function parseAction(action: IncomingDynamicAction, warnings: WebfilterDynamicWarning[]): WebfilterDynamicAction | null {
  if (!action || typeof action.type !== "string") {
    warnings.push({ code: "invalid-action", message: "Received malformed dynamic action." });
    return null;
  }

  if (action.type === "set-filter") {
    if (action.filter === "all" || action.filter === "allow" || action.filter === "block") {
      return { type: "set-filter", filter: action.filter };
    }
    warnings.push({ code: "invalid-filter", message: "Dynamic action 'set-filter' used unsupported filter value." });
    return null;
  }

  if (action.type === "set-auto-refresh") {
    if (typeof action.enabled === "boolean") {
      return { type: "set-auto-refresh", enabled: action.enabled };
    }
    warnings.push({ code: "invalid-auto-refresh", message: "Dynamic action 'set-auto-refresh' requires a boolean 'enabled'." });
    return null;
  }

  if (action.type === "schedule-refetch") {
    return {
      type: "schedule-refetch",
      delayMs: clampRefetchDelay(Number(action.delayMs ?? 30_000)),
    };
  }

  warnings.push({ code: "unsupported-action", message: `Ignored unsupported dynamic action '${action.type}'.` });
  return null;
}

export function toWebfilterDynamicEnvelope<TEntry>(
  result: IncomingWebfilterResult<TEntry>,
  now: Date = new Date(),
): WebfilterDynamicEnvelope<TEntry> {
  const warnings: WebfilterDynamicWarning[] = [];

  if (result.source && result.source !== "webfilter-ui") {
    warnings.push({
      code: "unsupported-source",
      message: `Ignored dynamic source '${result.source}'. Expected 'webfilter-ui'.`,
    });
  }

  const statePatch: WebfilterDynamicStatePatch<TEntry> = {
    diag: result.diag ?? null,
  };

  if (result.ok && result.entries) {
    statePatch.entries = result.entries;
    statePatch.error = null;
    statePatch.lastRefreshIso = now.toISOString();
    statePatch.lastRefreshLabel = now.toLocaleTimeString();
  } else {
    statePatch.error = (result.error ?? "Unknown error").trim() || "Unknown error";
  }

  if (Array.isArray(result.warnings)) {
    for (const item of result.warnings) {
      if (!item || typeof item.message !== "string" || item.message.trim().length === 0) {
        warnings.push({ code: "invalid-warning", message: "Received malformed warning item in dynamic payload." });
        continue;
      }
      warnings.push({ code: item.code?.trim() || "remote-warning", message: item.message.trim() });
    }
  }

  const actions: WebfilterDynamicAction[] = [];

  if (Array.isArray(result.actions)) {
    for (const action of result.actions) {
      const parsed = parseAction(action, warnings);
      if (parsed) actions.push(parsed);
    }
  }

  if (typeof result.timer === "number") {
    actions.push({ type: "schedule-refetch", delayMs: clampRefetchDelay(result.timer) });
  }

  if (typeof result.parameter?.autoRefresh === "boolean") {
    actions.push({ type: "set-auto-refresh", enabled: result.parameter.autoRefresh });
  }

  if (
    result.parameter?.filter === "all"
    || result.parameter?.filter === "allow"
    || result.parameter?.filter === "block"
  ) {
    actions.push({ type: "set-filter", filter: result.parameter.filter });
  }

  return {
    source: "webfilter-ui",
    statePatch,
    actions,
    warnings,
  };
}
