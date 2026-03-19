import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { getVersion } from "@tauri-apps/api/app";
import { parseWebfilterStatus, type WebfilterStatusResult } from "./webfilterStatus";
import { toWebfilterDynamicEnvelope } from "./webfilterDynamicProtocol";
import {
  applyPollJitterMs,
  formatRetryWaitSeconds,
  getWebfilterPollIntervalMs,
  isRetryReady,
  nextRetryDelayMs,
  SOURCE_POLL_MS,
  SOURCE_STALE_MS,
  type SourcePolicyKey,
} from "./sourcePollingPolicy";
import { searchTopic, type TopicNode } from "./topicSearch";
import { applySortToRows, toggleSort, type SortConfig } from "./tableSorting";
import "./App.css";

type ClientRow = {
  name: string;
  mac: string;
  ip: string;
};

type SettingsState = {
  baseUrl: string;
  loginUrl: string;
  dashboardUrl: string;
  username: string;
  apiUsername: string;
  apiKey: string;
  apiSecret: string;
  cookieHeader: string;
  pythonPath: string;
  dryRun: boolean;
  debug: boolean;
  msdUsername: string;
};

type ParseResult = {
  rows: ClientRow[];
  errors: string[];
  ignored: IgnoredRow[];
};

type IgnoredRow = {
  lineNumber: number;
  reason: string;
  raw: string;
  name?: string;
  mac?: string;
  ip?: string;
};

type SecondaryConflict = {
  row: ClientRow;
  field: "mac" | "ip";
};

type ConflictDeletePrompt = {
  incoming: ClientRow;
  existing: ClientRow;
  conflict: SecondaryConflict;
};

type BaseUrlCleanupPrompt = {
  enteredBaseUrl: string;
  suggestedBaseUrl: string;
};

type RunPayload = {
  incomingCsv: string;
  existingCsv: string;
  deleteCsv: string;
  updateMode: "skip" | "update";
  settings: SettingsState;
  iface?: string;
};

type RunRecord = {
  timestamp: string;
  lines: string[];
  exportCsv?: string;
  exportWlanbyodCsv?: string;
};

type UpdateInfo = Awaited<ReturnType<typeof check>>;

type FirewallLogEntry = {
  rulenr?: string;
  interface?: string;
  action?: string;
  dir?: string;
  protoname?: string;
  protonum?: string;
  src?: string;
  dst?: string;
  srcport?: string;
  dstport?: string;
  label?: string;
  counter?: number;
  __timestamp__?: string;
  reason?: string;
  tcpflags?: string;
  length?: string;
  error?: string;
};

type WfLogEntry = {
  action: string;
  user: string;
  ip: string;
  time: string;
  url: string;
  category: string;
};

type AnalysisDeviceRow = {
  ip: string;
  hostname: string;
  mac: string;
  user: string;
  segment: "Static Gruen" | "Static BYOD" | "Dynamic Gruen" | "Dynamic BYOD" | "Unknown";
  isStatic: boolean;
  isDynamic: boolean;
  fwPass: number;
  fwBlock: number;
  wfAllow: number;
  wfBlock: number;
  hasDualBlock: boolean;
  riskScore: number;
  identityConfidence: "high" | "medium" | "low";
  lastSeen: string;
};

type AnalysisTopItem = {
  label: string;
  count: number;
};

type AnalysisSegmentSummary = {
  segment: AnalysisDeviceRow["segment"];
  knownDevices: number;
  activeDevices: number;
  fwBlock: number;
  wfBlock: number;
  dualBlockDevices: number;
  avgRisk: number;
};

type AnalysisFinding = {
  severity: "high" | "medium" | "low";
  title: string;
  detail: string;
};

type AnalysisCategoryNode = TopicNode;

type AnalysisDeviceDetail = {
  row: AnalysisDeviceRow;
  staticLease: ClientRow | null;
  dynamicLease: DynamicLease | null;
  webfilterEvents: WfLogEntry[];
  firewallEvents: FirewallLogEntry[];
};

type SourceHealthKey = SourcePolicyKey;

type SourceHealthStatus = "idle" | "healthy" | "stale" | "error";

type SourceHealthEntry = {
  lastSuccessIso: string | null;
  lastError: string | null;
  lastErrorIso: string | null;
};

type SourceHealthView = {
  key: SourceHealthKey;
  status: SourceHealthStatus;
  label: string;
  lastSuccessLabel: string;
  detail: string;
};

type SourceRetryEntry = {
  attempt: number;
  nextRetryAtIso: string | null;
};

type WebfilterLogsInvokeResult = {
  ok: boolean;
  entries?: WfLogEntry[];
  error?: string;
  diag?: string;
  source?: string;
  actions?: Array<{ type?: string; filter?: string; enabled?: boolean; delayMs?: number }>;
  warnings?: Array<{ code?: string; message?: string }>;
  timer?: number;
  parameter?: {
    autoRefresh?: boolean;
    filter?: string;
  };
};

type WebfilterFetchResult = {
  ok: boolean;
  status: WebfilterStatusResult;
};

type WfAddressListType = "wl" | "bl";

type WfAddressListEntry = {
  id: string;
  name: string;
};

type WebfilterAddressListsInvokeResult = {
  ok: boolean;
  whitelistEntries?: WfAddressListEntry[];
  blacklistEntries?: WfAddressListEntry[];
  whitelistTotal?: number;
  blacklistTotal?: number;
  error?: string;
  diag?: string;
};

type WebfilterAddressListWriteInvokeResult = {
  ok: boolean;
  message?: string;
  error?: string;
  diag?: string;
  meta?: string;
  exportContent?: string;
  exportFilename?: string;
  importedLines?: number;
  warnings?: string[];
};

const SOURCE_LABELS: Record<SourceHealthKey, string> = {
  leases: "Leases (81)",
  "webfilter-ui": "Webfilter UI (80/1920)",
  "firewall-stream": "Firewall stream (81)",
};

const INITIAL_SOURCE_HEALTH: Record<SourceHealthKey, SourceHealthEntry> = {
  leases: { lastSuccessIso: null, lastError: null, lastErrorIso: null },
  "webfilter-ui": { lastSuccessIso: null, lastError: null, lastErrorIso: null },
  "firewall-stream": { lastSuccessIso: null, lastError: null, lastErrorIso: null },
};

const WEBFILTER_FAST_POLL_ERROR_COOLDOWN_MS = 60_000;

const INITIAL_SOURCE_RETRY: Record<SourceHealthKey, SourceRetryEntry> = {
  leases: { attempt: 0, nextRetryAtIso: null },
  "webfilter-ui": { attempt: 0, nextRetryAtIso: null },
  "firewall-stream": { attempt: 0, nextRetryAtIso: null },
};

function formatHealthTime(value: string | null): string {
  if (!value) return "never";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return "unknown";
  return new Date(ts).toLocaleTimeString();
}

function toSourceHealthView(
  key: SourceHealthKey,
  entry: SourceHealthEntry,
  retry: SourceRetryEntry,
  nowMillis: number,
): SourceHealthView {
  const label = SOURCE_LABELS[key];
  const lastSuccessLabel = formatHealthTime(entry.lastSuccessIso);
  const lastSuccessMillis = entry.lastSuccessIso ? Date.parse(entry.lastSuccessIso) : Number.NaN;
  const hasSuccess = Number.isFinite(lastSuccessMillis);
  const isStale = hasSuccess && nowMillis - lastSuccessMillis > SOURCE_STALE_MS[key];
  const isError = Boolean(entry.lastError);
  const waitSeconds = formatRetryWaitSeconds(retry.nextRetryAtIso, nowMillis);
  const retrySuffix = waitSeconds > 0 ? ` Retry in ~${waitSeconds}s.` : "";

  if (isError) {
    return {
      key,
      status: "error",
      label,
      lastSuccessLabel,
      detail: `${entry.lastError ?? "Source error"}${retrySuffix}`,
    };
  }
  if (!hasSuccess) {
    return {
      key,
      status: "idle",
      label,
      lastSuccessLabel,
      detail: "No successful refresh yet",
    };
  }
  if (isStale) {
    return {
      key,
      status: "stale",
      label,
      lastSuccessLabel,
      detail: "Data is stale",
    };
  }
  return {
    key,
    status: "healthy",
    label,
    lastSuccessLabel,
    detail: "Healthy",
  };
}

function isPrivateIpv4(ip: string): boolean {
  if (!ip) return false;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  return false;
}

function toTimeMillis(value: string): number {
  if (!value) return 0;
  const ts = Date.parse(value);
  return Number.isNaN(ts) ? 0 : ts;
}

function classifyDynamicSegment(iface: string): "Dynamic Gruen" | "Dynamic BYOD" {
  const value = iface.trim().toLowerCase();
  if (value.includes("byod") || value.includes("wlan") || value.includes("opt4")) {
    return "Dynamic BYOD";
  }
  return "Dynamic Gruen";
}

function clampRisk(value: number): number {
  if (value < 0) return 0;
  if (value > 100) return 100;
  return Math.round(value);
}

function isGatewayRouterIp(ipRaw: string): boolean {
  const ip = ipRaw.trim();
  const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  const octets = match.slice(1).map((value) => Number(value));
  if (octets.some((value) => Number.isNaN(value) || value < 0 || value > 255)) return false;
  return octets[3] === 1;
}

function normalizeWebfilterUser(userRaw: string): string {
  const user = userRaw.trim();
  if (!user) return "";
  // LBOX-* identities represent the filter appliance itself, not an end user.
  if (/^LBOX-[A-Z0-9-]+$/i.test(user)) return "";
  return user;
}

const MAX_FW_LOG_ENTRIES = 500;

const DEFAULT_SETTINGS: SettingsState = {
  baseUrl: "https://your-opnsense-host:81",
  loginUrl: "https://your-opnsense-host:81",
  dashboardUrl: "https://your-opnsense-host:81/ui/core/dashboard",
  username: "",
  apiUsername: "",
  apiKey: "",
  apiSecret: "",
  cookieHeader: "",
  pythonPath: "python",
  dryRun: false,
  debug: false,
  msdUsername: "",
};

function normalizeBaseUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim();
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed);
    if (parsed.port !== "81") {
      parsed.port = "81";
    }
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return trimmed;
  }
}

function deriveUrlsFromBase(baseUrl: string): Pick<SettingsState, "baseUrl" | "loginUrl" | "dashboardUrl"> {
  const enteredBase = baseUrl;
  const dashboardBase = enteredBase.trim().replace(/\/+$/, "");
  if (!dashboardBase) {
    return {
      baseUrl: "",
      loginUrl: "",
      dashboardUrl: "",
    };
  }
  return {
    baseUrl: enteredBase,
    loginUrl: enteredBase,
    dashboardUrl: `${dashboardBase}/ui/core/dashboard`,
  };
}

function suggestCleanedUrls(baseUrl: string): Pick<SettingsState, "baseUrl" | "loginUrl" | "dashboardUrl"> {
  return deriveUrlsFromBase(normalizeBaseUrl(baseUrl));
}

function normalizeSettings(loaded?: Partial<SettingsState> | null): SettingsState {
  if (!loaded) return DEFAULT_SETTINGS;
  const baseSource = loaded.baseUrl ?? loaded.loginUrl ?? DEFAULT_SETTINGS.baseUrl;
  return {
    ...DEFAULT_SETTINGS,
    ...loaded,
    ...deriveUrlsFromBase(baseSource),
  };
}

function rowKey(row: ClientRow): string {
  return `${row.name}|${row.mac}|${row.ip}`;
}

function buildIncomingCsv(rows: ClientRow[]): string {
  const lines = ["Name;MAC;IP", ...rows.map((row) => `${row.name};${row.mac};${row.ip}`)];
  return lines.join("\n");
}

function buildDeleteCsv(rows: ClientRow[]): string {
  const lines = ["Name;MAC;IP", ...rows.map((row) => `${row.name};${row.mac};${row.ip}`)];
  return lines.join("\n");
}

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === ";" && !inQuotes) {
      values.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  values.push(current);
  return values;
}

function parseCsvRows(text: string): string[] {
  const rows: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];

    if (char === '"') {
      if (inQuotes && text[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if ((char === "\n" || char === "\r") && !inQuotes) {
      if (char === "\r" && text[i + 1] === "\n") {
        i += 1;
      }
      const trimmed = current.trim();
      if (trimmed.length > 0) rows.push(trimmed);
      current = "";
      continue;
    }

    current += char;
  }

  const trimmed = current.trim();
  if (trimmed.length > 0) rows.push(trimmed);
  return rows;
}

function pickColumnIndex(indexMap: Map<string, number>, keys: string[]): number | undefined {
  for (const key of keys) {
    const index = indexMap.get(key);
    if (index !== undefined) return index;
  }
  return undefined;
}

const MAC_RE = /^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$/;
const IP_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function parseCsv(text: string): ParseResult {
  const errors: string[] = [];
  const rows: ClientRow[] = [];
  const ignored: IgnoredRow[] = [];
  const lines = parseCsvRows(text);

  if (lines.length === 0) {
    return { rows, errors, ignored };
  }

  const header = parseCsvLine(lines[0]).map((h) => h.trim().toLowerCase());
  const indexMap = new Map<string, number>();
  header.forEach((h, i) => indexMap.set(h, i));

  const nameIndex = pickColumnIndex(indexMap, ["name", "geraet"]);
  const macIndex = pickColumnIndex(indexMap, ["mac", "mac-adresse", "macadresse"]);
  const ipIndex = pickColumnIndex(indexMap, ["ip", "ip-adresse", "ipadresse"]);

  if (nameIndex === undefined || macIndex === undefined || ipIndex === undefined) {
    const reason = "Missing required columns: Name/Geraet, MAC, IP (extra columns are ignored)";
    errors.push(reason);
    ignored.push({
      lineNumber: 1,
      reason,
      raw: lines[0] ?? "",
    });
    return { rows, errors, ignored };
  }

  lines.slice(1).forEach((line, idx) => {
    const parts = parseCsvLine(line);
    const name = (parts[nameIndex] ?? "").trim();
    const mac = (parts[macIndex] ?? "").trim();
    const ip = (parts[ipIndex] ?? "").trim();

    if (!name || !mac || !ip) {
      const missing: string[] = [];
      if (!name) missing.push("Name");
      if (!mac) missing.push("MAC");
      if (!ip) missing.push("IP");
      ignored.push({
        lineNumber: idx + 2,
        reason: `Missing fields: ${missing.join(", ")}`,
        raw: line,
        name,
        mac,
        ip,
      });
      return;
    }
    if (!MAC_RE.test(mac)) {
      ignored.push({
        lineNumber: idx + 2,
        reason: `Invalid MAC ${mac}`,
        raw: line,
        name,
        mac,
        ip,
      });
      return;
    }
    if (!IP_RE.test(ip)) {
      ignored.push({
        lineNumber: idx + 2,
        reason: `Invalid IP ${ip}`,
        raw: line,
        name,
        mac,
        ip,
      });
      return;
    }
    rows.push({ name, mac, ip });
  });

  return { rows, errors, ignored };
}

function suggestAvailableIp(preferredIp: string, rows: ClientRow[]): string | undefined {
  if (!IP_RE.test(preferredIp)) return undefined;
  const parts = preferredIp.split(".").map((value) => Number(value));
  if (parts.length !== 4 || parts.some((value) => Number.isNaN(value))) return undefined;
  const used = new Set(rows.map((row) => row.ip));
  if (!used.has(preferredIp)) return preferredIp;
  const [first, second, third] = parts;
  for (let host = 2; host < 255; host += 1) {
    const candidate = `${first}.${second}.${third}.${host}`;
    if (!used.has(candidate)) return candidate;
  }
  return undefined;
}

function suggestAvailableName(preferredName: string, rows: ClientRow[]): string | undefined {
  const base = preferredName.trim() || "dynamic-lease";
  const used = new Set(rows.map((row) => row.name.trim().toLowerCase()));
  if (!used.has(base.toLowerCase())) return base;
  for (let suffix = 2; suffix < 1000; suffix += 1) {
    const candidate = `${base}-${suffix}`;
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
  return undefined;
}

function evaluateMoveConflicts(existingRows: ClientRow[], draft: MoveDynamicDraft): MoveConflictInfo {
  const ip = draft.ip.trim();
  const mac = draft.mac.trim().toLowerCase();
  const hostname = draft.hostname.trim().toLowerCase();
  const alreadyExists = existingRows.find(
    (row) => row.ip === ip && row.mac.trim().toLowerCase() === mac && row.name.trim().toLowerCase() === hostname,
  );
  const ipConflict = existingRows.find((row) => row.ip === ip && row.mac.trim().toLowerCase() !== mac);
  const macConflict = existingRows.find((row) => row.mac.trim().toLowerCase() === mac && row.ip !== ip);
  const nameConflict = existingRows.find(
    (row) => row.name.trim().toLowerCase() === hostname && row.mac.trim().toLowerCase() !== mac,
  );
  return {
    alreadyExists,
    ipConflict,
    macConflict,
    nameConflict,
    suggestedIp: ipConflict ? suggestAvailableIp(ip, existingRows) : undefined,
    suggestedName: nameConflict ? suggestAvailableName(draft.hostname, existingRows) : undefined,
  };
}

function getDynamicRowBadges(lease: DynamicLease, existingRows: ClientRow[]): string[] {
  const hostname = (lease.hostname || "").trim().toLowerCase();
  const mac = lease.mac.trim().toLowerCase();
  const ip = lease.ip.trim();
  const same = existingRows.find(
    (row) =>
      row.ip === ip &&
      row.mac.trim().toLowerCase() === mac &&
      row.name.trim().toLowerCase() === hostname,
  );
  if (same) return ["Exists"];

  const badges: string[] = [];
  const ipTaken = existingRows.some((row) => row.ip === ip && row.mac.trim().toLowerCase() !== mac);
  const macTaken = existingRows.some((row) => row.mac.trim().toLowerCase() === mac && row.ip !== ip);
  const nameTaken = hostname
    ? existingRows.some((row) => row.name.trim().toLowerCase() === hostname && row.mac.trim().toLowerCase() !== mac)
    : false;

  if (ipTaken) badges.push("IP taken");
  if (nameTaken) badges.push("Name taken");
  if (macTaken) badges.push("MAC taken");
  return badges;
}

type HelpResult = {
  ok: boolean;
  lines: string[];
  value?: string | null;
};

type ApiBootstrapResult = {
  ok: boolean;
  lines: string[];
  settings: SettingsState;
};

type DynamicLease = {
  iface: string;
  ip: string;
  mac: string;
  hostname: string;
  start: string;
  end: string;
  status: string;
  online: boolean;
  movableToStatic: boolean;
};

type DynamicLeasesResult = {
  ok: boolean;
  rows: DynamicLease[];
  movableCount: number;
  infoCount: number;
  leaseSource: string;
  leaseSourceDetail: string;
};

type MoveDynamicLeasePayload = {
  settings: SettingsState;
  iface: string;
  ip: string;
  mac: string;
  hostname: string;
};

type MoveDynamicLeaseResult = {
  ok: boolean;
  status: string;
  message: string;
};

type UpdateStaticFromDynamicPayload = {
  settings: SettingsState;
  oldMac: string;
  iface: string;
  ip: string;
  mac: string;
  hostname: string;
};

type UpdateStaticFromDynamicResult = {
  ok: boolean;
  status: string;
  message: string;
};

type MoveDynamicDraft = {
  iface: string;
  ip: string;
  mac: string;
  hostname: string;
};

type MoveConflictInfo = {
  alreadyExists?: ClientRow;
  ipConflict?: ClientRow;
  macConflict?: ClientRow;
  nameConflict?: ClientRow;
  suggestedIp?: string;
  suggestedName?: string;
};

function fwFormatTime(ts?: string): string {
  if (!ts) return "-";
  return ts.slice(11, 19); // extract HH:MM:SS from ISO timestamp
}

function fwBadgeClass(action?: string): string {
  if (action === "pass") return "fw-badge-pass";
  if (action === "block" || action === "drop") return "fw-badge-block";
  if (action === "rdr") return "fw-badge-rdr";
  return "fw-badge-other";
}

function fwRowClass(action?: string): string {
  if (action === "block" || action === "drop") return "fw-row-block";
  if (action === "rdr") return "fw-row-rdr";
  return "";
}

function App() {
  const UPDATE_MODE: RunPayload["updateMode"] = "update";
  const [activeTab, setActiveTab] = useState<"leases" | "settings" | "history" | "help" | "firewall" | "webfilter" | "analysis">("leases");
  const [settings, setSettings] = useState<SettingsState>(DEFAULT_SETTINGS);
  const [history, setHistory] = useState<RunRecord[]>([]);
  const [incomingCsv, setIncomingCsv] = useState("");
  const [existingCsv, setExistingCsv] = useState("");
  const [confirmChanges, setConfirmChanges] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [passwordInput, setPasswordInput] = useState("");
  const [hasPassword, setHasPassword] = useState(false);
  const [msdPasswordInput, setMsdPasswordInput] = useState("");
  const [hasMsdPassword, setHasMsdPassword] = useState(false);
  const [helpLogs, setHelpLogs] = useState<string[]>([]);
  const [helpBusy, setHelpBusy] = useState(false);
  const [excludedAddKeys, setExcludedAddKeys] = useState<Set<string>>(new Set());
  const [excludedConflictKeys, setExcludedConflictKeys] = useState<Set<string>>(new Set());
  const [selectedDeleteKeys, setSelectedDeleteKeys] = useState<Set<string>>(new Set());
    const [forcedDeleteRows, setForcedDeleteRows] = useState<Record<string, ClientRow>>({});
    const [deletePrompt, setDeletePrompt] = useState<ConflictDeletePrompt | null>(null);
    const [baseUrlCleanupPrompt, setBaseUrlCleanupPrompt] = useState<BaseUrlCleanupPrompt | null>(null);
  const [autoExporting, setAutoExporting] = useState(false);
  const [lastAutoExportKey, setLastAutoExportKey] = useState<string | null>(null);
  const [autoExportPrompt, setAutoExportPrompt] = useState(false);
  const [acknowledgeIgnored, setAcknowledgeIgnored] = useState(false);
  const [activeProcess, setActiveProcess] = useState<"run" | "export" | null>(null);
  const [cancelRequested, setCancelRequested] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [showUpdatePrompt, setShowUpdatePrompt] = useState(false);
  const [updateBusy, setUpdateBusy] = useState(false);
  const [updateInstalling, setUpdateInstalling] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<string | null>(null);
  const [addCollapsed, setAddCollapsed] = useState(false);
  const [editCollapsed, setEditCollapsed] = useState(false);
  const [deleteCollapsed, setDeleteCollapsed] = useState(false);
  const [exactCollapsed, setExactCollapsed] = useState(true);
  const [appVersion, setAppVersion] = useState<string | null>(null);
  const [leaseView, setLeaseView] = useState<"static" | "staticWlanbyod" | "dynamic" | "review" | "runlog">("static");
  const [dynamicLeases, setDynamicLeases] = useState<DynamicLease[]>([]);
  const [dynamicBusy, setDynamicBusy] = useState(false);
  const [dynamicError, setDynamicError] = useState<string | null>(null);
  const [staticRefreshBusy, setStaticRefreshBusy] = useState(false);
  const [dynamicMeta, setDynamicMeta] = useState<{
    movableCount: number;
    infoCount: number;
    leaseSource: string;
    leaseSourceDetail: string;
  } | null>(null);
  const [moveDynamicPrompt, setMoveDynamicPrompt] = useState<MoveDynamicDraft | null>(null);
  const [moveDynamicBusy, setMoveDynamicBusy] = useState(false);
  const [updateStaticIpSelected, setUpdateStaticIpSelected] = useState(true);
  const [updateStaticMacSelected, setUpdateStaticMacSelected] = useState(true);

  // WLANBYOD (opt4) static lease state
  const [incomingCsvW, setIncomingCsvW] = useState("");
  const [existingCsvW, setExistingCsvW] = useState("");
  const [excludedAddKeysW, setExcludedAddKeysW] = useState<Set<string>>(new Set());
  const [excludedConflictKeysW, setExcludedConflictKeysW] = useState<Set<string>>(new Set());
  const [selectedDeleteKeysW, setSelectedDeleteKeysW] = useState<Set<string>>(new Set());
  const [forcedDeleteRowsW, setForcedDeleteRowsW] = useState<Record<string, ClientRow>>({});
  const [deletePromptW, setDeletePromptW] = useState<ConflictDeletePrompt | null>(null);
  const [confirmChangesW, setConfirmChangesW] = useState(false);
  const [acknowledgeIgnoredW, setAcknowledgeIgnoredW] = useState(false);
  const [addCollapsedW, setAddCollapsedW] = useState(false);
  const [editCollapsedW, setEditCollapsedW] = useState(false);
  const [deleteCollapsedW, setDeleteCollapsedW] = useState(false);
  const [exactCollapsedW, setExactCollapsedW] = useState(true);

  // Firewall log stream state
  const [fwLogs, setFwLogs] = useState<FirewallLogEntry[]>([]);
  const [fwStreaming, setFwStreaming] = useState(false);
  const [fwError, setFwError] = useState<string | null>(null);
  const [fwFilter, setFwFilter] = useState<"all" | "pass" | "block" | "rdr">("all");

  const incoming = useMemo(() => parseCsv(incomingCsv), [incomingCsv]);
  const existing = useMemo(() => parseCsv(existingCsv), [existingCsv]);
  const incomingW = useMemo(() => parseCsv(incomingCsvW), [incomingCsvW]);
  const existingW = useMemo(() => parseCsv(existingCsvW), [existingCsvW]);

  const fwLogsFiltered = useMemo(() => {
    if (fwFilter === "all") return fwLogs;
    if (fwFilter === "block") return fwLogs.filter((e) => e.action === "block" || e.action === "drop");
    return fwLogs.filter((e) => e.action === fwFilter);
  }, [fwLogs, fwFilter]);

  const [wfLogs, setWfLogs] = useState<WfLogEntry[]>([]);
  const [wfLogsBusy, setWfLogsBusy] = useState(false);
  const [analysisRefreshBusy, setAnalysisRefreshBusy] = useState(false);
  const [wfLogsError, setWfLogsError] = useState<string | null>(null);
  const [wfLogFilter, setWfLogFilter] = useState<"all" | "allow" | "block">("all");
  const [wfView, setWfView] = useState<"logs" | "address-lists">("logs");
  const [wfAutoRefresh, setWfAutoRefresh] = useState(false);
  const [wfLastRefresh, setWfLastRefresh] = useState<string | null>(null);
  const [wfDiag, setWfDiag] = useState<string | null>(null);
  const [wfProtocolWarnings, setWfProtocolWarnings] = useState<string[]>([]);
  const [wfAddressListType, setWfAddressListType] = useState<WfAddressListType>("wl");
  const [wfWhitelistEntries, setWfWhitelistEntries] = useState<WfAddressListEntry[]>([]);
  const [wfBlacklistEntries, setWfBlacklistEntries] = useState<WfAddressListEntry[]>([]);
  const [wfWhitelistTotal, setWfWhitelistTotal] = useState(0);
  const [wfBlacklistTotal, setWfBlacklistTotal] = useState(0);
  const [wfAddressBusy, setWfAddressBusy] = useState(false);
  const [wfAddressActionBusy, setWfAddressActionBusy] = useState(false);
  const [wfAddressError, setWfAddressError] = useState<string | null>(null);
  const [wfAddressSearch, setWfAddressSearch] = useState("");
  const [wfAddressNewValue, setWfAddressNewValue] = useState("");
  const [wfAddressImportText, setWfAddressImportText] = useState("");
  const [wfAddressEditId, setWfAddressEditId] = useState<string | null>(null);
  const [wfAddressEditOriginalName, setWfAddressEditOriginalName] = useState("");
  const [wfAddressEditValue, setWfAddressEditValue] = useState("");
  const [wfAddressSelectedIds, setWfAddressSelectedIds] = useState<Set<string>>(new Set());
  const [sourceHealth, setSourceHealth] = useState<Record<SourceHealthKey, SourceHealthEntry>>(INITIAL_SOURCE_HEALTH);
  const [sourceRetry, setSourceRetry] = useState<Record<SourceHealthKey, SourceRetryEntry>>(INITIAL_SOURCE_RETRY);
  const [healthTick, setHealthTick] = useState(0);
  const [topicSearchPattern, setTopicSearchPattern] = useState("");
  const [selectedRiskDeviceIps, setSelectedRiskDeviceIps] = useState<Set<string>>(new Set());
  const [selectedAnalysisDeviceIp, setSelectedAnalysisDeviceIp] = useState<string | null>(null);
  const [riskyDeviceSort, setRiskyDeviceSort] = useState<SortConfig>(null);
  const [allDevicesSort, setAllDevicesSort] = useState<SortConfig>(null);
  const [unknownIpsSort, setUnknownIpsSort] = useState<SortConfig>(null);
  const wfScheduledRefetchRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (wfScheduledRefetchRef.current !== null) {
        window.clearTimeout(wfScheduledRefetchRef.current);
        wfScheduledRefetchRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    const id = window.setInterval(() => {
      setHealthTick((prev) => prev + 1);
    }, 15_000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    setWfAddressSelectedIds(new Set());
    setWfAddressEditId(null);
    setWfAddressEditOriginalName("");
    setWfAddressEditValue("");
  }, [wfAddressListType]);

  function markSourceSuccess(key: SourceHealthKey) {
    setSourceHealth((prev) => ({
      ...prev,
      [key]: {
        lastSuccessIso: new Date().toISOString(),
        lastError: null,
      },
    }));
    setSourceRetry((prev) => ({
      ...prev,
      [key]: {
        attempt: 0,
        nextRetryAtIso: null,
      },
    }));
  }

  function markSourceError(key: SourceHealthKey, error: string) {
    setSourceHealth((prev) => ({
      ...prev,
      [key]: {
        ...prev[key],
        lastError: error.trim() || "Unknown error",
        lastErrorIso: new Date().toISOString(),
      },
    }));
  }

  function scheduleSourceRetry(key: SourceHealthKey) {
    setSourceRetry((prev) => {
      const delayMs = nextRetryDelayMs(key, prev[key].attempt);
      return {
        ...prev,
        [key]: {
          attempt: prev[key].attempt + 1,
          nextRetryAtIso: new Date(Date.now() + delayMs).toISOString(),
        },
      };
    });
  }

  function canRunSourceNow(key: SourceHealthKey): boolean {
    return isRetryReady(sourceRetry[key].nextRetryAtIso, Date.now());
  }

  const sourceHealthViews = useMemo(() => {
    const nowMillis = Date.now();
    return (Object.keys(sourceHealth) as SourceHealthKey[]).map((key) =>
      toSourceHealthView(key, sourceHealth[key], sourceRetry[key], nowMillis));
  }, [sourceHealth, sourceRetry, healthTick]);

  const wfLogsFiltered = useMemo(() => {
    if (wfLogFilter === "all") return wfLogs;
    return wfLogs.filter((e) => e.action.toLowerCase() === wfLogFilter);
  }, [wfLogs, wfLogFilter]);

  const wfAddressEntries = useMemo(
    () => (wfAddressListType === "wl" ? wfWhitelistEntries : wfBlacklistEntries),
    [wfAddressListType, wfWhitelistEntries, wfBlacklistEntries],
  );

  const wfAddressEntriesFiltered = useMemo(() => {
    const needle = wfAddressSearch.trim().toLowerCase();
    if (!needle) return wfAddressEntries;
    return wfAddressEntries.filter((entry) => entry.name.toLowerCase().includes(needle));
  }, [wfAddressEntries, wfAddressSearch]);

  const wfAddressTotal = wfAddressListType === "wl" ? wfWhitelistTotal : wfBlacklistTotal;

  const wfSelectedCount = useMemo(
    () => wfAddressEntries.reduce((sum, entry) => sum + (wfAddressSelectedIds.has(entry.id) ? 1 : 0), 0),
    [wfAddressEntries, wfAddressSelectedIds],
  );

  const analysis = useMemo(() => {
    const byIp = new Map<string, AnalysisDeviceRow>();
    const knownIps = new Set<string>();
    const segmentKnownIps = new Map<AnalysisDeviceRow["segment"], Set<string>>([
      ["Static Gruen", new Set<string>()],
      ["Static BYOD", new Set<string>()],
      ["Dynamic Gruen", new Set<string>()],
      ["Dynamic BYOD", new Set<string>()],
      ["Unknown", new Set<string>()],
    ]);
    const userToIps = new Map<string, Set<string>>();

    const ensure = (ipRaw: string): AnalysisDeviceRow | null => {
      const ip = ipRaw.trim();
      if (!ip) return null;
      const existingRow = byIp.get(ip);
      if (existingRow) return existingRow;
      const row: AnalysisDeviceRow = {
        ip,
        hostname: isGatewayRouterIp(ip) ? "TFK-Router" : "",
        mac: "",
        user: "",
        segment: "Unknown",
        isStatic: false,
        isDynamic: false,
        fwPass: 0,
        fwBlock: 0,
        wfAllow: 0,
        wfBlock: 0,
        hasDualBlock: false,
        riskScore: 0,
        identityConfidence: "low",
        lastSeen: "",
      };
      byIp.set(ip, row);
      return row;
    };

    const markSeen = (row: AnalysisDeviceRow, seenValue: string) => {
      if (!seenValue) return;
      if (!row.lastSeen || toTimeMillis(seenValue) >= toTimeMillis(row.lastSeen)) {
        row.lastSeen = seenValue;
      }
    };

    for (const lease of [...existing.rows, ...existingW.rows]) {
      const row = ensure(lease.ip);
      if (!row) continue;
      row.isStatic = true;
      row.segment = existingW.rows.includes(lease) ? "Static BYOD" : "Static Gruen";
      if (!row.hostname && lease.name) row.hostname = lease.name;
      if (!row.mac && lease.mac) row.mac = lease.mac;
      if (isGatewayRouterIp(row.ip)) row.hostname = "TFK-Router";
      knownIps.add(row.ip);
      const segmentSet = segmentKnownIps.get(row.segment);
      if (segmentSet) segmentSet.add(row.ip);
    }

    for (const lease of dynamicLeases) {
      const row = ensure(lease.ip);
      if (!row) continue;
      row.isDynamic = true;
      if (!row.isStatic) {
        row.segment = classifyDynamicSegment(lease.iface);
      }
      if (!row.hostname && lease.hostname) row.hostname = lease.hostname;
      if (!row.mac && lease.mac) row.mac = lease.mac;
      if (isGatewayRouterIp(row.ip)) row.hostname = "TFK-Router";
      knownIps.add(row.ip);
      const segmentSet = segmentKnownIps.get(row.segment);
      if (segmentSet) segmentSet.add(row.ip);
      markSeen(row, lease.end || lease.start);
    }

    const blockedCategoryMap = new Map<string, number>();
    const blockedHostMap = new Map<string, number>();
    const blockedUsers = new Map<string, number>();
    const categoryHostMap = new Map<string, Map<string, number>>();

    for (const wf of wfLogs) {
      const row = ensure(wf.ip);
      if (!row) continue;
      knownIps.add(row.ip);
      const action = wf.action.toLowerCase();
      if (action === "block") {
        row.wfBlock += 1;
      } else if (action === "allow") {
        row.wfAllow += 1;
      }
      const normalizedUser = normalizeWebfilterUser(wf.user);
      if (!row.user && normalizedUser) row.user = normalizedUser;
      if (normalizedUser) {
        const key = normalizedUser;
        const ips = userToIps.get(key) ?? new Set<string>();
        ips.add(row.ip);
        userToIps.set(key, ips);
        if (action === "block") {
          blockedUsers.set(key, (blockedUsers.get(key) ?? 0) + 1);
        }
      }
      markSeen(row, wf.time);

      if (action === "block") {
        const cat = wf.category?.trim() || "unknown";
        blockedCategoryMap.set(cat, (blockedCategoryMap.get(cat) ?? 0) + 1);
        let host = "unknown";
        try {
          host = new URL(wf.url).hostname || "unknown";
        } catch {
          host = (wf.url || "").split("/")[0] || "unknown";
        }
        blockedHostMap.set(host, (blockedHostMap.get(host) ?? 0) + 1);
        const hostByCategory = categoryHostMap.get(cat) ?? new Map<string, number>();
        hostByCategory.set(host, (hostByCategory.get(host) ?? 0) + 1);
        categoryHostMap.set(cat, hostByCategory);
      }
    }

    const unknownFirewallIps = new Map<string, { pass: number; block: number }>();
    for (const fw of fwLogs) {
      const action = (fw.action || "").toLowerCase();
      const isPass = action === "pass";
      const isBlock = action === "block" || action === "drop";
      const candidates = Array.from(new Set([fw.src?.trim() ?? "", fw.dst?.trim() ?? ""]))
        .filter((ip) => ip.length > 0);
      for (const ip of candidates) {
        if (knownIps.has(ip)) {
          const row = ensure(ip);
          if (!row) continue;
          if (isPass) row.fwPass += 1;
          if (isBlock) row.fwBlock += 1;
          markSeen(row, fw.__timestamp__ || "");
          continue;
        }
        if (!isPrivateIpv4(ip)) continue;
        const agg = unknownFirewallIps.get(ip) ?? { pass: 0, block: 0 };
        if (isPass) agg.pass += 1;
        if (isBlock) agg.block += 1;
        unknownFirewallIps.set(ip, agg);
      }
    }

    const rows = Array.from(byIp.values())
      .map((row) => {
        row.hasDualBlock = row.fwBlock > 0 && row.wfBlock > 0;
        const hasWebActivity = row.wfAllow + row.wfBlock > 0;
        const hasIdentity = Boolean(row.mac.trim() || row.hostname.trim() || row.user.trim());
        if (row.isStatic && row.mac.trim() && row.hostname.trim()) {
          row.identityConfidence = "high";
        } else if (hasIdentity) {
          row.identityConfidence = "medium";
        } else {
          row.identityConfidence = "low";
        }

        let risk = row.fwBlock * 6 + row.wfBlock * 4;
        if (row.hasDualBlock) risk += 8;
        if (row.segment === "Unknown") risk += 8;
        if (hasWebActivity && !row.user.trim()) risk += 3;
        if (row.identityConfidence === "low" && (row.fwBlock > 0 || row.wfBlock > 0)) risk += 2;
        row.riskScore = clampRisk(risk);
        return row;
      })
      .filter((r) => r.fwPass + r.fwBlock + r.wfAllow + r.wfBlock > 0)
      .sort((a, b) => {
        const scoreA = a.riskScore * 10 + a.fwBlock * 3 + a.wfBlock * 2 + a.fwPass + a.wfAllow;
        const scoreB = b.riskScore * 10 + b.fwBlock * 3 + b.wfBlock * 2 + b.fwPass + b.wfAllow;
        return scoreB - scoreA;
      });

    const topBlockedCategories: AnalysisTopItem[] = Array.from(blockedCategoryMap.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    const topBlockedHosts: AnalysisTopItem[] = Array.from(blockedHostMap.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    const unknownActiveIps = Array.from(unknownFirewallIps.entries())
      .map(([ip, counts]) => ({ ip, ...counts }))
      .sort((a, b) => b.block + b.pass - (a.block + a.pass))
      .slice(0, 12);

    const correlatedBlocks = rows.filter((row) => row.fwBlock > 0 && row.wfBlock > 0).length;
    const highRiskCount = rows.filter((row) => row.riskScore >= 50).length;
    const fwOnlyBlocked = rows.filter((row) => row.fwBlock > 0 && row.wfBlock === 0).length;
    const wfOnlyBlocked = rows.filter((row) => row.wfBlock > 0 && row.fwBlock === 0).length;

    const segments: AnalysisDeviceRow["segment"][] = [
      "Static Gruen",
      "Static BYOD",
      "Dynamic Gruen",
      "Dynamic BYOD",
      "Unknown",
    ];

    const segmentSummary: AnalysisSegmentSummary[] = segments.map((segment) => {
      const active = rows.filter((row) => row.segment === segment);
      const known = segmentKnownIps.get(segment) ?? new Set<string>();
      const fwBlock = active.reduce((sum, row) => sum + row.fwBlock, 0);
      const wfBlock = active.reduce((sum, row) => sum + row.wfBlock, 0);
      const dual = active.filter((row) => row.hasDualBlock).length;
      const avgRisk = active.length > 0
        ? Math.round(active.reduce((sum, row) => sum + row.riskScore, 0) / active.length)
        : 0;
      return {
        segment,
        knownDevices: known.size,
        activeDevices: active.length,
        fwBlock,
        wfBlock,
        dualBlockDevices: dual,
        avgRisk,
      };
    });

    const riskyDevices = rows.slice(0, 15);

    const findings: AnalysisFinding[] = [];
    const topUnknown = unknownActiveIps[0];
    if (topUnknown && topUnknown.block >= 5) {
      findings.push({
        severity: topUnknown.block >= 20 ? "high" : "medium",
        title: "Unknown private IP with repeated firewall blocks",
        detail: `${topUnknown.ip} triggered ${topUnknown.block} blocked firewall events.`,
      });
    }

    const multiIpUsers = Array.from(userToIps.entries())
      .filter(([, ips]) => ips.size >= 3)
      .sort((a, b) => b[1].size - a[1].size);
    if (multiIpUsers.length > 0) {
      const [user, ips] = multiIpUsers[0];
      findings.push({
        severity: ips.size >= 5 ? "high" : "medium",
        title: "Single user seen on multiple IPs",
        detail: `${user} appeared on ${ips.size} distinct IPs in webfilter activity.`,
      });
    }

    if (correlatedBlocks > 0) {
      findings.push({
        severity: correlatedBlocks >= 5 ? "high" : "medium",
        title: "Dual-layer blocking detected",
        detail: `${correlatedBlocks} devices were blocked by both firewall and webfilter.`,
      });
    }

    const staleStatic = (segmentKnownIps.get("Static Gruen")?.size ?? 0) + (segmentKnownIps.get("Static BYOD")?.size ?? 0)
      - rows.filter((row) => row.segment === "Static Gruen" || row.segment === "Static BYOD").length;
    if (staleStatic > 0) {
      findings.push({
        severity: "low",
        title: "Static devices without observed activity",
        detail: `${staleStatic} static lease entries are currently inactive in correlated logs.`,
      });
    }

    const topBlockedUsers: AnalysisTopItem[] = Array.from(blockedUsers.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    const categoryNodes: AnalysisCategoryNode[] = Array.from(categoryHostMap.entries())
      .map(([name, hosts]) => {
        const topHosts = Array.from(hosts.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3)
          .map(([host]) => host);
        const count = Array.from(hosts.values()).reduce((sum, value) => sum + value, 0);
        return {
          id: `cat-${name}`,
          name,
          description: topHosts.length > 0 ? `Hosts: ${topHosts.join(", ")}` : "Hosts: unknown",
          count,
        };
      })
      .sort((a, b) => b.count - a.count);

    return {
      rows,
      riskyDevices,
      topBlockedCategories,
      topBlockedHosts,
      topBlockedUsers,
      categoryNodes,
      unknownActiveIps,
      segmentSummary,
      findings,
      correlatedBlocks,
      highRiskCount,
      fwOnlyBlocked,
      wfOnlyBlocked,
      knownDeviceCount: byIp.size,
    };
  }, [existing.rows, existingW.rows, dynamicLeases, wfLogs, fwLogs]);

  const sortedRiskyDevices = useMemo(
    () => applySortToRows(analysis.riskyDevices, riskyDeviceSort),
    [analysis.riskyDevices, riskyDeviceSort]
  );

  const sortedAllDevices = useMemo(
    () => applySortToRows(analysis.rows, allDevicesSort),
    [analysis.rows, allDevicesSort]
  );

  const sortedUnknownIps = useMemo(
    () => applySortToRows(analysis.unknownActiveIps, unknownIpsSort),
    [analysis.unknownActiveIps, unknownIpsSort]
  );

  const filteredCategoryNodes = useMemo(() => {
    return searchTopic(topicSearchPattern, analysis.categoryNodes).slice(0, 15);
  }, [topicSearchPattern, analysis.categoryNodes]);

  const selectedAnalysisDeviceDetail = useMemo<AnalysisDeviceDetail | null>(() => {
    if (!selectedAnalysisDeviceIp) return null;
    const row = analysis.rows.find((item) => item.ip === selectedAnalysisDeviceIp);
    if (!row) return null;

    const staticLease = [...existing.rows, ...existingW.rows].find((lease) => lease.ip === row.ip) ?? null;
    const dynamicLease = dynamicLeases.find(
      (lease) => lease.ip === row.ip || (row.mac.trim() && lease.mac.toLowerCase() === row.mac.toLowerCase()),
    ) ?? null;

    const webfilterEvents = wfLogs
      .filter((event) => event.ip === row.ip)
      .sort((a, b) => toTimeMillis(b.time) - toTimeMillis(a.time))
      .slice(0, 60);

    const firewallEvents = fwLogs
      .filter((event) => (event.src ?? "").trim() === row.ip || (event.dst ?? "").trim() === row.ip)
      .sort((a, b) => toTimeMillis(b.__timestamp__ ?? "") - toTimeMillis(a.__timestamp__ ?? ""))
      .slice(0, 80);

    return {
      row,
      staticLease,
      dynamicLease,
      webfilterEvents,
      firewallEvents,
    };
  }, [selectedAnalysisDeviceIp, analysis.rows, existing.rows, existingW.rows, dynamicLeases, wfLogs, fwLogs]);

  const allRiskDeviceIps = analysis.riskyDevices.map((row) => row.ip);

  const allRiskDevicesSelected = allRiskDeviceIps.length > 0
    && allRiskDeviceIps.every((ip) => selectedRiskDeviceIps.has(ip));

  useEffect(() => {
    setSelectedRiskDeviceIps((prev) => {
      const allowed = new Set(allRiskDeviceIps);
      const next = new Set<string>();
      prev.forEach((ip) => {
        if (allowed.has(ip)) next.add(ip);
      });
      return next;
    });
  }, [allRiskDeviceIps.join("|")]);

  function toggleAllRiskDevices() {
    if (allRiskDeviceIps.length === 0) return;
    if (allRiskDevicesSelected) {
      setSelectedRiskDeviceIps(new Set());
      return;
    }
    setSelectedRiskDeviceIps(new Set(allRiskDeviceIps));
  }

  function toggleRiskDevice(ip: string) {
    setSelectedRiskDeviceIps((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) {
        next.delete(ip);
      } else {
        next.add(ip);
      }
      return next;
    });
  }

  const handleSort = useCallback((tableId: string, column: string) => {
    if (tableId === 'risky') {
      setRiskyDeviceSort(prev => toggleSort(prev, column));
    } else if (tableId === 'all') {
      setAllDevicesSort(prev => toggleSort(prev, column));
    } else if (tableId === 'unknown') {
      setUnknownIpsSort(prev => toggleSort(prev, column));
    }
  }, []);

  const showLeaseViews = activeTab !== "firewall" && activeTab !== "webfilter" && activeTab !== "analysis";

  const diff = useMemo(() => {
    const exact: ClientRow[] = [];
    const conflicts: { incoming: ClientRow; existing: ClientRow }[] = [];
    const adds: ClientRow[] = [];
    const duplicates: ClientRow[] = [];
    const deletes: ClientRow[] = [];

    const seen = new Set<string>();
    const existingRows = existing.rows;

    const isExact = (row: ClientRow, other: ClientRow) =>
      row.name === other.name && row.mac === other.mac && row.ip === other.ip;

    const isAnyMatch = (row: ClientRow, other: ClientRow) =>
      row.name === other.name || row.mac === other.mac || row.ip === other.ip;

    incoming.rows.forEach((row) => {
      const key = rowKey(row);
      if (seen.has(key)) {
        duplicates.push(row);
        return;
      }
      seen.add(key);

      const match = existingRows.find((item) => isAnyMatch(row, item));
      if (!match) {
        adds.push(row);
        return;
      }
      if (isExact(row, match)) {
        exact.push(row);
      } else {
        conflicts.push({ incoming: row, existing: match });
      }
    });

    existingRows.forEach((row) => {
      const match = incoming.rows.find((item) => isAnyMatch(item, row));
      if (!match) {
        deletes.push(row);
      }
    });

    return { exact, conflicts, adds, duplicates, deletes };
  }, [incoming.rows, existing.rows]);

  const diffW = useMemo(() => {
    const exact: ClientRow[] = [];
    const conflicts: { incoming: ClientRow; existing: ClientRow }[] = [];
    const adds: ClientRow[] = [];
    const duplicates: ClientRow[] = [];
    const deletes: ClientRow[] = [];
    const seen = new Set<string>();
    const existingRows = existingW.rows;
    const isExact = (row: ClientRow, other: ClientRow) =>
      row.name === other.name && row.mac === other.mac && row.ip === other.ip;
    const isAnyMatch = (row: ClientRow, other: ClientRow) =>
      row.name === other.name || row.mac === other.mac || row.ip === other.ip;
    incomingW.rows.forEach((row) => {
      const key = rowKey(row);
      if (seen.has(key)) { duplicates.push(row); return; }
      seen.add(key);
      const match = existingRows.find((item) => isAnyMatch(row, item));
      if (!match) { adds.push(row); return; }
      if (isExact(row, match)) { exact.push(row); } else { conflicts.push({ incoming: row, existing: match }); }
    });
    existingRows.forEach((row) => {
      const match = incomingW.rows.find((item) => isAnyMatch(item, row));
      if (!match) { deletes.push(row); }
    });
    return { exact, conflicts, adds, duplicates, deletes };
  }, [incomingW.rows, existingW.rows]);

  useEffect(() => {
    setExcludedAddKeys(new Set());
    setExcludedConflictKeys(new Set());
    setSelectedDeleteKeys(new Set());
    setAcknowledgeIgnored(false);
    setExactCollapsed(true);
  }, [incomingCsv, existingCsv]);

  useEffect(() => {
    setExcludedAddKeysW(new Set());
    setExcludedConflictKeysW(new Set());
    setSelectedDeleteKeysW(new Set());
    setAcknowledgeIgnoredW(false);
    setExactCollapsedW(true);
  }, [incomingCsvW, existingCsvW]);

  const credentialsReady = settings.username.trim().length > 0 && hasPassword;
  const hasRealUrls =
    settings.baseUrl.trim() !== DEFAULT_SETTINGS.baseUrl &&
    settings.baseUrl.trim().length > 0;
  const canAutoExport = settingsLoaded && credentialsReady && hasRealUrls;
  const autoExportKey = canAutoExport
    ? `${settings.baseUrl}|${settings.loginUrl}|${settings.dashboardUrl}|${settings.username}`
    : null;
  const canExport = credentialsReady;
  const hasIgnored = incoming.ignored.length > 0 || existing.ignored.length > 0;
  const showRunOverlay = (isRunning || autoExporting) && !autoExportPrompt;
  const runOverlayTitle = activeProcess === "run" ? "Running changes" : "Exporting static list";
  const showUpdateOverlay = showUpdatePrompt || updateInstalling;
  const forcedDeleteKeys = useMemo(() => new Set(Object.keys(forcedDeleteRows)), [forcedDeleteRows]);
  const displayDeletes = useMemo(() => {
    const map = new Map<string, ClientRow>();
    diff.deletes.forEach((row) => map.set(rowKey(row), row));
    Object.values(forcedDeleteRows).forEach((row) => map.set(rowKey(row), row));
    return Array.from(map.values());
  }, [diff.deletes, forcedDeleteRows]);
  const deletableDeletes = useMemo(
    () => displayDeletes.filter((row) => !forcedDeleteKeys.has(rowKey(row))),
    [displayDeletes, forcedDeleteKeys],
  );
  const forcedDeleteKeysW = useMemo(() => new Set(Object.keys(forcedDeleteRowsW)), [forcedDeleteRowsW]);
  const displayDeletesW = useMemo(() => {
    const map = new Map<string, ClientRow>();
    diffW.deletes.forEach((row) => map.set(rowKey(row), row));
    Object.values(forcedDeleteRowsW).forEach((row) => map.set(rowKey(row), row));
    return Array.from(map.values());
  }, [diffW.deletes, forcedDeleteRowsW]);
  const deletableDeletesW = useMemo(
    () => displayDeletesW.filter((row) => !forcedDeleteKeysW.has(rowKey(row))),
    [displayDeletesW, forcedDeleteKeysW],
  );

  const canRun =
    incoming.rows.length > 0 &&
    incoming.errors.length === 0 &&
    existing.errors.length === 0 &&
    (!hasIgnored || acknowledgeIgnored) &&
    confirmChanges &&
    credentialsReady;

  const allAddsChecked = diff.adds.length > 0 && diff.adds.every((row) => !excludedAddKeys.has(rowKey(row)));
  const allConflictsChecked =
    diff.conflicts.length > 0 &&
    diff.conflicts.every(({ incoming }) => !excludedConflictKeys.has(rowKey(incoming)));
  const allDeletesChecked =
    deletableDeletes.length > 0 && deletableDeletes.every((row) => selectedDeleteKeys.has(rowKey(row)));

  const runBlockers = [
    incoming.rows.length === 0 ? "Incoming CSV is empty" : null,
    incoming.errors.length > 0 ? "Incoming CSV has validation errors" : null,
    existing.errors.length > 0 ? "Existing CSV has validation errors" : null,
    hasIgnored && !acknowledgeIgnored ? "Acknowledge ignored rows to continue" : null,
    settings.username.trim().length === 0 ? "Enter a username in Settings" : null,
    !hasPassword ? "Save a password in Settings" : null,
    !confirmChanges ? "Confirm the changes to enable running" : null,
  ].filter(Boolean) as string[];

  const hasIgnoredW = incomingW.ignored.length > 0 || existingW.ignored.length > 0;
  const canRunW =
    incomingW.rows.length > 0 &&
    incomingW.errors.length === 0 &&
    existingW.errors.length === 0 &&
    (!hasIgnoredW || acknowledgeIgnoredW) &&
    confirmChangesW &&
    credentialsReady;
  const allAddsCheckedW = diffW.adds.length > 0 && diffW.adds.every((row) => !excludedAddKeysW.has(rowKey(row)));
  const allConflictsCheckedW =
    diffW.conflicts.length > 0 &&
    diffW.conflicts.every(({ incoming: r }) => !excludedConflictKeysW.has(rowKey(r)));
  const allDeletesCheckedW =
    deletableDeletesW.length > 0 && deletableDeletesW.every((row) => selectedDeleteKeysW.has(rowKey(row)));
  const runBlockersW = [
    incomingW.rows.length === 0 ? "Incoming CSV is empty" : null,
    incomingW.errors.length > 0 ? "Incoming CSV has validation errors" : null,
    existingW.errors.length > 0 ? "Existing CSV has validation errors" : null,
    hasIgnoredW && !acknowledgeIgnoredW ? "Acknowledge ignored rows to continue" : null,
    settings.username.trim().length === 0 ? "Enter a username in Settings" : null,
    !hasPassword ? "Save a password in Settings" : null,
    !confirmChangesW ? "Confirm the changes to enable running" : null,
  ].filter(Boolean) as string[];
  const existingByMac = useMemo(() => {
    const map = new Map<string, ClientRow>();
    existing.rows.forEach((row) => map.set(row.mac.toLowerCase(), row));
    return map;
  }, [existing.rows]);

  const existingByIp = useMemo(() => {
    const map = new Map<string, ClientRow>();
    existing.rows.forEach((row) => map.set(row.ip, row));
    return map;
  }, [existing.rows]);

  const existingByMacW = useMemo(() => {
    const map = new Map<string, ClientRow>();
    existingW.rows.forEach((row) => map.set(row.mac.toLowerCase(), row));
    return map;
  }, [existingW.rows]);
  const existingByIpW = useMemo(() => {
    const map = new Map<string, ClientRow>();
    existingW.rows.forEach((row) => map.set(row.ip, row));
    return map;
  }, [existingW.rows]);

  const moveDynamicIp = moveDynamicPrompt?.ip.trim() ?? "";
  const moveDynamicMac = moveDynamicPrompt?.mac.trim() ?? "";
  const moveDynamicName = moveDynamicPrompt?.hostname.trim() ?? "";
  const moveDynamicIpValid = moveDynamicIp.length > 0 && IP_RE.test(moveDynamicIp);
  const moveDynamicMacValid = moveDynamicMac.length > 0 && MAC_RE.test(moveDynamicMac);
  const moveDynamicNameValid = moveDynamicName.length > 0;
  const moveConflicts = moveDynamicPrompt ? evaluateMoveConflicts(existing.rows, moveDynamicPrompt) : undefined;
  const moveConflictTarget =
    moveConflicts?.ipConflict ?? moveConflicts?.nameConflict ?? moveConflicts?.macConflict ?? moveConflicts?.alreadyExists;
  const canSubmitMoveDynamic =
    !!moveDynamicPrompt &&
    moveDynamicIpValid &&
    moveDynamicMacValid &&
    moveDynamicNameValid &&
    !moveConflicts?.ipConflict &&
    !moveConflicts?.macConflict &&
    !moveConflicts?.nameConflict &&
    !moveConflicts?.alreadyExists;

  function findSecondaryConflict(incoming: ClientRow, existingRow: ClientRow): SecondaryConflict | null {
    if (incoming.mac !== existingRow.mac) {
      const match = existingByMac.get(incoming.mac.toLowerCase());
      if (match && rowKey(match) !== rowKey(existingRow)) {
        return { row: match, field: "mac" };
      }
    }
    if (incoming.ip !== existingRow.ip) {
      const match = existingByIp.get(incoming.ip);
      if (match && rowKey(match) !== rowKey(existingRow)) {
        return { row: match, field: "ip" };
      }
    }
    return null;
  }

  function findSecondaryConflictW(incoming: ClientRow, existingRow: ClientRow): SecondaryConflict | null {
    if (incoming.mac !== existingRow.mac) {
      const match = existingByMacW.get(incoming.mac.toLowerCase());
      if (match && rowKey(match) !== rowKey(existingRow)) {
        return { row: match, field: "mac" };
      }
    }
    if (incoming.ip !== existingRow.ip) {
      const match = existingByIpW.get(incoming.ip);
      if (match && rowKey(match) !== rowKey(existingRow)) {
        return { row: match, field: "ip" };
      }
    }
    return null;
  }

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let active = true;
    (async () => {
      const handle = await listen<string>("run-log", (event) => {
        setLogs((prev) => [...prev, String(event.payload)]);
      });
      if (!active) {
        handle();
        return;
      }
      unlisten = handle;
    })();

    invoke<SettingsState | null>("load_settings")
      .then((loaded) => {
        if (loaded) setSettings(normalizeSettings(loaded));
      })
      .catch(() => undefined)
      .finally(() => setSettingsLoaded(true));

    invoke<RunRecord[]>("load_history")
      .then((loaded) => setHistory(loaded))
      .catch(() => undefined);

    invoke<boolean>("has_password")
      .then((value) => setHasPassword(value))
      .catch(() => setHasPassword(false));

    invoke<boolean>("has_msd_password")
      .then((value) => setHasMsdPassword(value))
      .catch(() => setHasMsdPassword(false));

    return () => {
      active = false;
      if (unlisten) unlisten();
    };
  }, []);

  useEffect(() => {
    if (import.meta.env.DEV) return;
    checkForUpdates({ silent: true }).catch(() => undefined);
  }, []);

  useEffect(() => {
    getVersion().then(setAppVersion).catch(() => setAppVersion(null));
  }, []);

  useEffect(() => {
    if (!settingsLoaded) return;
    invoke("save_settings", { settings }).catch(() => undefined);
  }, [settings, settingsLoaded]);

  useEffect(() => {
    if (!canAutoExport || !autoExportKey) return;
    if (autoExporting) return;
    if (lastAutoExportKey === autoExportKey) return;
    if (!autoExportPrompt) {
      setAutoExportPrompt(true);
    }
  }, [autoExportKey, autoExporting, canAutoExport, lastAutoExportKey, settings]);

  useEffect(() => {
    if (leaseView !== "dynamic") return;
    if (dynamicBusy) return;
    if (dynamicLeases.length > 0) return;
    if (!credentialsReady) return;
    void handleLoadDynamicLeases();
  }, [leaseView, dynamicBusy, dynamicLeases.length, credentialsReady]);

  // Firewall log stream event listeners
  useEffect(() => {
    const unlistenEntry = listen<string>("firewall-log-entry", (event) => {
      try {
        const entry = JSON.parse(event.payload) as FirewallLogEntry;
        if (entry.error) {
          setFwError(entry.error);
          markSourceError("firewall-stream", entry.error);
          setFwStreaming(false);
          return;
        }
        markSourceSuccess("firewall-stream");
        setFwLogs((prev) => {
          const next = [...prev, entry];
          return next.length > MAX_FW_LOG_ENTRIES ? next.slice(next.length - MAX_FW_LOG_ENTRIES) : next;
        });
      } catch (_) {
        // ignore parse failures
      }
    });
    const unlistenStopped = listen<void>("firewall-log-stopped", () => {
      setFwStreaming(false);
    });
    return () => {
      void unlistenEntry.then((fn) => fn());
      void unlistenStopped.then((fn) => fn());
    };
  }, []);

  // Auto-fetch webfilter logs when switching to the tab (if no data yet)
  useEffect(() => {
    if (activeTab !== "webfilter") return;
    if (wfLogs.length > 0) return;
    if (!settings.msdUsername.trim() || !hasMsdPassword) return;
    void handleFetchWfLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  useEffect(() => {
    if (activeTab !== "webfilter") return;
    if (wfView !== "address-lists") return;
    if (!settings.msdUsername.trim() || !hasMsdPassword) return;
    if (wfWhitelistEntries.length > 0 || wfBlacklistEntries.length > 0) return;
    void handleFetchWfAddressLists();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, wfView]);

  // Auto-refresh webfilter logs with adaptive near-stream pacing.
  useEffect(() => {
    if (!wfAutoRefresh) return;
    let cancelled = false;
    let timeoutId: number | null = null;

    const scheduleNext = () => {
      if (cancelled) return;
      const isInteractiveView = activeTab === "webfilter" || activeTab === "analysis";
      const isDocumentVisible = typeof document === "undefined" || document.visibilityState === "visible";
      const webfilterHealth = sourceHealth["webfilter-ui"];
      const lastErrorMs = webfilterHealth.lastErrorIso ? Date.parse(webfilterHealth.lastErrorIso) : Number.NaN;
      const hasCooldownError = Number.isFinite(lastErrorMs)
        && Date.now() - lastErrorMs <= WEBFILTER_FAST_POLL_ERROR_COOLDOWN_MS;
      const hasRecentError = Boolean(webfilterHealth.lastError)
        || hasCooldownError
        || sourceRetry["webfilter-ui"].attempt > 0;
      const baseMs = getWebfilterPollIntervalMs({
        isInteractiveView,
        isDocumentVisible,
        hasRecentError,
      });
      const delayMs = applyPollJitterMs(baseMs);

      timeoutId = window.setTimeout(async () => {
        if (cancelled) return;
        if (!canRunSourceNow("webfilter-ui")) {
          scheduleNext();
          return;
        }
        if (!settings.msdUsername.trim() || !hasMsdPassword) {
          scheduleNext();
          return;
        }
        await handleFetchWfLogs();
        scheduleNext();
      }, delayMs);
    };

    scheduleNext();

    return () => {
      cancelled = true;
      if (timeoutId !== null) {
        window.clearTimeout(timeoutId);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wfAutoRefresh, activeTab, sourceRetry]);

  // Bootstrap analysis dependencies when the tab becomes active.
  useEffect(() => {
    if (activeTab !== "analysis") return;

    void refreshLeasesSilently();

    if (!wfAutoRefresh) {
      setWfAutoRefresh(true);
    }

    if (settings.msdUsername.trim() && hasMsdPassword) {
      if (!canRunSourceNow("webfilter-ui")) return;
      void handleFetchWfLogs();
    }

    if (!fwStreaming && canRunSourceNow("firewall-stream")) {
      void handleStartFwLog();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  // Keep lease data fresh while analysis is open.
  useEffect(() => {
    if (activeTab !== "analysis") return;
    if (!credentialsReady) return;
    const id = window.setInterval(() => {
      if (!canRunSourceNow("leases")) return;
      void refreshLeasesSilently();
    }, SOURCE_POLL_MS.leases);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, credentialsReady, sourceRetry]);

  // Stream watchdog with fallback restart and retry/backoff.
  useEffect(() => {
    if (!fwStreaming) return;
    if (activeTab !== "analysis" && activeTab !== "firewall") return;
    const id = window.setInterval(() => {
      const lastSuccessIso = sourceHealth["firewall-stream"].lastSuccessIso;
      if (!lastSuccessIso) return;
      const lastSuccess = Date.parse(lastSuccessIso);
      if (Number.isNaN(lastSuccess)) return;
      const isStale = Date.now() - lastSuccess > SOURCE_STALE_MS["firewall-stream"];
      if (!isStale) return;
      if (!canRunSourceNow("firewall-stream")) return;
      setLogs((prev) => [...prev, "Firewall stream stale. Attempting fallback restart..."]);
      void handleStartFwLog();
    }, SOURCE_POLL_MS["firewall-stream"]);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fwStreaming, activeTab, sourceHealth, sourceRetry]);

  async function handleAutoExportConfirm() {
    if (!autoExportKey) return;
    setAutoExportPrompt(false);
    setCancelRequested(false);
    setActiveProcess("export");
    setAutoExporting(true);
    setLogs([]);
    try {
      const settingsForExport = await bootstrapApiDataIfNeeded(settings);
      const result = await invoke<RunRecord>("export_static", { payload: { settings: settingsForExport } });
      setHistory((prev) => [result, ...prev]);
      if (result.exportCsv) {
        setExistingCsv(result.exportCsv);
      }
      if (result.exportWlanbyodCsv) {
        setExistingCsvW(result.exportWlanbyodCsv);
      }
      setLastAutoExportKey(autoExportKey);
    } catch (error) {
      setRunError(String(error));
    } finally {
      setAutoExporting(false);
      setActiveProcess(null);
    }
  }

  function handleAutoExportCancel() {
    if (autoExportKey) {
      setLastAutoExportKey(autoExportKey);
    }
    setAutoExportPrompt(false);
  }

  function hasApiData(candidate: SettingsState): boolean {
    return (
      candidate.apiKey.trim().length > 0 &&
      candidate.apiSecret.trim().length > 0
    );
  }

  function buildApiPulledLines(candidate: SettingsState): string[] {
    return [
      `API username: ${candidate.apiUsername || "-"}`,
      `API key: ${candidate.apiKey || "-"}`,
      `API secret: ${candidate.apiSecret || "-"}`,
    ];
  }

  async function bootstrapApiDataIfNeeded(candidate: SettingsState): Promise<SettingsState> {
    if (hasApiData(candidate)) {
      return candidate;
    }
    const result = await invoke<ApiBootstrapResult>("discover_api_credentials", {
      payload: { settings: candidate },
    });
    const nextSettings = normalizeSettings(result.settings);
    setSettings(nextSettings);
    setLogs((prev) => [...prev, ...result.lines, ...buildApiPulledLines(nextSettings)]);
    return nextSettings;
  }

  async function handleSaveSettings() {
    try {
      await invoke("save_settings", { settings });
      const hasNewPassword = passwordInput.trim().length > 0;
      if (passwordInput.trim().length > 0) {
        await invoke("save_password", { password: passwordInput });
        setPasswordInput("");
        setHasPassword(true);
      }
      if (msdPasswordInput.trim().length > 0) {
        await invoke("save_msd_password", { password: msdPasswordInput });
        setMsdPasswordInput("");
        setHasMsdPassword(true);
      }
      setLogs([hasNewPassword || msdPasswordInput.trim().length > 0 ? "Settings and password(s) saved." : "Settings saved."]);

      const missingApiData =
        settings.apiUsername.trim().length === 0 ||
        settings.apiKey.trim().length === 0 ||
        settings.apiSecret.trim().length === 0;
      const hasPasswordNow = hasPassword || hasNewPassword;
      if (
        missingApiData &&
        settings.username.trim().length > 0 &&
        hasPasswordNow &&
        hasRealUrls
      ) {
        await bootstrapApiDataIfNeeded(settings);
      }

      if (settings.username.trim().length > 0 && hasPasswordNow && hasRealUrls) {
        setAutoExportPrompt(true);
      }
    } catch (error) {
      setRunError(String(error));
    } finally {
      setAutoExporting(false);
    }
  }

  async function handlePickCsv(target: "incoming" | "existing") {
    try {
      const selected = await open({
        multiple: false,
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (!selected) return;
      const filePath = Array.isArray(selected) ? selected[0] : selected;
      if (!filePath) return;
      const text = await invoke<string>("read_text_file", { path: String(filePath) });
      if (target === "incoming") {
        setIncomingCsv(text);
      } else {
        setExistingCsv(text);
      }
    } catch (error) {
      setRunError(`CSV import failed: ${error}`);
      setLogs([`CSV import failed: ${error}`]);
    }
  }

  async function handlePickCsvW(target: "incoming" | "existing") {
    try {
      const selected = await open({
        multiple: false,
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (!selected) return;
      const filePath = Array.isArray(selected) ? selected[0] : selected;
      if (!filePath) return;
      const text = await invoke<string>("read_text_file", { path: String(filePath) });
      if (target === "incoming") {
        setIncomingCsvW(text);
      } else {
        setExistingCsvW(text);
      }
    } catch (error) {
      setRunError(`CSV import failed: ${error}`);
      setLogs([`CSV import failed: ${error}`]);
    }
  }

  async function handleRun() {
    if (!credentialsReady) {
      setRunError("Username and saved password are required.");
      setLogs(["Missing credentials. Open Settings to save them."]);
      return;
    }
    setCancelRequested(false);
    setActiveProcess("run");
    setIsRunning(true);
    setRunError(null);
    setLogs([]);
    try {
      let existingCsvForRun = existingCsv;
      const addKeys = new Set(diff.adds.map(rowKey));
      const conflictKeys = new Set(diff.conflicts.map(({ incoming }) => rowKey(incoming)));
      const filteredRows = incoming.rows.filter((row) => {
        const key = rowKey(row);
        if (addKeys.has(key) && excludedAddKeys.has(key)) return false;
        if (conflictKeys.has(key) && excludedConflictKeys.has(key)) return false;
        return true;
      });
      const filteredIncomingCsv = buildIncomingCsv(filteredRows);
      const deleteRows = displayDeletes.filter((row) => selectedDeleteKeys.has(rowKey(row)));
      const deleteCsv = buildDeleteCsv(deleteRows);
      if (existingCsv.trim().length === 0) {
        const settingsForExport = await bootstrapApiDataIfNeeded(settings);
        const exportResult = await invoke<RunRecord>("export_static", { payload: { settings: settingsForExport } });
        setHistory((prev) => [exportResult, ...prev]);
        if (exportResult.exportCsv) {
          existingCsvForRun = exportResult.exportCsv;
          setExistingCsv(exportResult.exportCsv);
        }
        if (exportResult.exportWlanbyodCsv) {
          setExistingCsvW(exportResult.exportWlanbyodCsv);
        }
      }
      const payload: RunPayload = {
        incomingCsv: filteredIncomingCsv,
        existingCsv: existingCsvForRun,
        deleteCsv,
        updateMode: UPDATE_MODE,
        settings,
      };
      const result = await invoke<RunRecord>("run_dhcp", { payload });
      setHistory((prev) => [result, ...prev]);

      const settingsForRefresh = await bootstrapApiDataIfNeeded(settings);
      const refreshedList = await invoke<RunRecord>("export_static", {
        payload: { settings: settingsForRefresh },
      });
      setHistory((prev) => [refreshedList, ...prev]);
      if (refreshedList.exportCsv) {
        setExistingCsv(refreshedList.exportCsv);
      }
      if (refreshedList.exportWlanbyodCsv) {
        setExistingCsvW(refreshedList.exportWlanbyodCsv);
      }
    } catch (error) {
      setRunError(String(error));
      setLogs(["Run failed. See error details."]);
    } finally {
      setIsRunning(false);
      setActiveProcess(null);
    }
  }

  async function handleRunW() {
    if (!credentialsReady) {
      setRunError("Username and saved password are required.");
      setLogs(["Missing credentials. Open Settings to save them."]);
      return;
    }
    setCancelRequested(false);
    setActiveProcess("run");
    setIsRunning(true);
    setRunError(null);
    setLogs([]);
    try {
      let existingCsvForRun = existingCsvW;
      const addKeys = new Set(diffW.adds.map(rowKey));
      const conflictKeys = new Set(diffW.conflicts.map(({ incoming: r }) => rowKey(r)));
      const filteredRows = incomingW.rows.filter((row) => {
        const key = rowKey(row);
        if (addKeys.has(key) && excludedAddKeysW.has(key)) return false;
        if (conflictKeys.has(key) && excludedConflictKeysW.has(key)) return false;
        return true;
      });
      const filteredIncomingCsv = buildIncomingCsv(filteredRows);
      const deleteRows = displayDeletesW.filter((row) => selectedDeleteKeysW.has(rowKey(row)));
      const deleteCsv = buildDeleteCsv(deleteRows);
      if (existingCsvW.trim().length === 0) {
        const settingsForExport = await bootstrapApiDataIfNeeded(settings);
        const exportResult = await invoke<RunRecord>("export_static", { payload: { settings: settingsForExport } });
        setHistory((prev) => [exportResult, ...prev]);
        if (exportResult.exportWlanbyodCsv) {
          existingCsvForRun = exportResult.exportWlanbyodCsv;
          setExistingCsvW(exportResult.exportWlanbyodCsv);
        } else if (exportResult.exportCsv) {
          existingCsvForRun = exportResult.exportCsv;
          setExistingCsvW(exportResult.exportCsv);
        }
        if (exportResult.exportCsv) {
          setExistingCsv(exportResult.exportCsv);
        }
      }
      const payload: RunPayload = {
        incomingCsv: filteredIncomingCsv,
        existingCsv: existingCsvForRun,
        deleteCsv,
        updateMode: UPDATE_MODE,
        settings,
        iface: "opt4",
      };
      const result = await invoke<RunRecord>("run_dhcp", { payload });
      setHistory((prev) => [result, ...prev]);
      const settingsForRefresh = await bootstrapApiDataIfNeeded(settings);
      const refreshedList = await invoke<RunRecord>("export_static", {
        payload: { settings: settingsForRefresh },
      });
      setHistory((prev) => [refreshedList, ...prev]);
      if (refreshedList.exportWlanbyodCsv) {
        setExistingCsvW(refreshedList.exportWlanbyodCsv);
      } else if (refreshedList.exportCsv) {
        setExistingCsvW(refreshedList.exportCsv);
      }
      if (refreshedList.exportCsv) {
        setExistingCsv(refreshedList.exportCsv);
      }
    } catch (error) {
      setRunError(String(error));
      setLogs(["Run failed. See error details."]);
    } finally {
      setIsRunning(false);
      setActiveProcess(null);
    }
  }

  async function handleExport() {
    if (!credentialsReady) {
      setRunError("Username and saved password are required.");
      setLogs(["Missing credentials. Open Settings to save them."]);
      return;
    }
    setCancelRequested(false);
    setActiveProcess("export");
    setIsRunning(true);
    setRunError(null);
    setLogs([]);
    try {
      const settingsForExport = await bootstrapApiDataIfNeeded(settings);
      const savePath = await save({
        filters: [{ name: "CSV", extensions: ["csv"] }],
        defaultPath: "export_static.csv",
      });
      if (!savePath) {
        setLogs(["Export canceled."]);
        return;
      }
      const result = await invoke<RunRecord>("export_static", {
        payload: { settings: settingsForExport, savePath },
      });
      setHistory((prev) => [result, ...prev]);
      if (result.exportCsv) {
        setExistingCsv(result.exportCsv);
      }
    } catch (error) {
      setRunError(String(error));
      setLogs(["Export failed. See error details."]);
    } finally {
      setIsRunning(false);
      setActiveProcess(null);
    }
  }

  async function handleExportW() {
    if (!credentialsReady) {
      setRunError("Username and saved password are required.");
      setLogs(["Missing credentials. Open Settings to save them."]);
      return;
    }
    setCancelRequested(false);
    setActiveProcess("export");
    setIsRunning(true);
    setRunError(null);
    setLogs([]);
    try {
      const settingsForExport = await bootstrapApiDataIfNeeded(settings);
      const savePath = await save({
        filters: [{ name: "CSV", extensions: ["csv"] }],
        defaultPath: "export_static_wlanbyod.csv",
      });
      if (!savePath) {
        setLogs(["Export canceled."]);
        return;
      }
      const result = await invoke<RunRecord>("export_static", {
        payload: { settings: settingsForExport, savePath },
      });
      setHistory((prev) => [result, ...prev]);
      if (result.exportWlanbyodCsv) {
        setExistingCsvW(result.exportWlanbyodCsv);
      } else if (result.exportCsv) {
        setExistingCsvW(result.exportCsv);
      }
      if (result.exportCsv) {
        setExistingCsv(result.exportCsv);
      }
    } catch (error) {
      setRunError(String(error));
      setLogs(["Export failed. See error details."]);
    } finally {
      setIsRunning(false);
      setActiveProcess(null);
    }
  }

  async function handleLoadDynamicLeases(options: { silent?: boolean } = {}) {
    const { silent = false } = options;
    if (!credentialsReady) {
      if (!silent) setDynamicError("Username and saved password are required.");
      return;
    }
    setDynamicBusy(true);
    if (!silent) setDynamicError(null);
    try {
      const settingsForFetch = await bootstrapApiDataIfNeeded(settings);
      const result = await invoke<DynamicLeasesResult>("load_dynamic_leases", {
        payload: { settings: settingsForFetch },
      });
      setDynamicLeases(result.rows);
      setDynamicMeta({
        movableCount: result.movableCount,
        infoCount: result.infoCount,
        leaseSource: result.leaseSource,
        leaseSourceDetail: result.leaseSourceDetail,
      });
      if (!silent) {
        const logLine = `Dynamic leases loaded: total=${result.rows.length}, movable=${result.movableCount}, info=${result.infoCount}`;
        setLogs((prev) => [...prev, logLine]);
        const record: RunRecord = {
          timestamp: new Date().toISOString(),
          lines: [
            "Dynamic lease fetch",
            logLine,
            `Lease source: ${result.leaseSource}`,
            `Lease source detail: ${result.leaseSourceDetail}`,
          ],
        };
        setHistory((prev) => [record, ...prev]);
      }
      markSourceSuccess("leases");
    } catch (error) {
      markSourceError("leases", String(error));
      scheduleSourceRetry("leases");
      if (!silent) setDynamicError(String(error));
    } finally {
      setDynamicBusy(false);
    }
  }

  async function refreshStaticLeases(options: { silent?: boolean } = {}) {
    const { silent = false } = options;
    setStaticRefreshBusy(true);
    if (!credentialsReady) {
      if (!silent) {
        setRunError("Username and saved password are required.");
        setLogs((prev) => [...prev, "Static refresh blocked: missing username/password."]);
      }
      setStaticRefreshBusy(false);
      return;
    }
    try {
      if (!silent) {
        setRunError(null);
        setLogs((prev) => [...prev, "Refreshing static leases..."]);
      }
      const settingsForExport = await bootstrapApiDataIfNeeded(settings);
      const result = await invoke<RunRecord>("export_static", { payload: { settings: settingsForExport } });
      if (result.exportCsv) {
        setExistingCsv(result.exportCsv);
      }
      if (result.exportWlanbyodCsv) {
        setExistingCsvW(result.exportWlanbyodCsv);
      }
      if (!silent) {
        setHistory((prev) => [result, ...prev]);
        setLogs((prev) => [...prev, "Static leases refreshed."]);
      }
      markSourceSuccess("leases");
    } catch (error) {
      markSourceError("leases", String(error));
      scheduleSourceRetry("leases");
      if (!silent) {
        setRunError(String(error));
        setLogs((prev) => [...prev, `Static refresh failed: ${error}`]);
      }
    } finally {
      setStaticRefreshBusy(false);
    }
  }

  async function refreshLeasesSilently() {
    await Promise.all([
      handleLoadDynamicLeases({ silent: true }),
      refreshStaticLeases({ silent: true }),
    ]);
  }

  async function checkForUpdates(options: { silent?: boolean } = {}) {
    const { silent = false } = options;
    if (updateBusy || updateInstalling) return;
    setUpdateBusy(true);
    if (!silent) setUpdateStatus("Checking for updates...");
    try {
      const update = await check();
      if (update?.available) {
        setUpdateInfo(update);
        setShowUpdatePrompt(true);
        setUpdateStatus(`Update available: v${update.version}`);
      } else {
        setUpdateInfo(null);
        if (!silent) setUpdateStatus("You're up to date.");
      }
    } catch (error) {
      if (!silent) setUpdateStatus(`Update check failed: ${error}`);
    } finally {
      setUpdateBusy(false);
    }
  }

  async function installUpdate() {
    if (!updateInfo) return;
    setUpdateInstalling(true);
    setUpdateStatus("Downloading update...");
    try {
      await updateInfo.downloadAndInstall();
      await relaunch();
    } catch (error) {
      setUpdateStatus(`Update failed: ${error}`);
      setUpdateInstalling(false);
    }
  }

  async function handleStartFwLog() {
    setFwError(null);
    setFwStreaming(true);
    try {
      await invoke("start_firewall_log_stream", { settings });
    } catch (err) {
      setFwError(String(err));
      markSourceError("firewall-stream", String(err));
      scheduleSourceRetry("firewall-stream");
      setFwStreaming(false);
    }
  }

  function handleStopFwLog() {
    void invoke("stop_firewall_log_stream");
    setFwStreaming(false);
  }

  async function handleFetchWfLogs(): Promise<WebfilterFetchResult> {
    setWfLogsBusy(true);
    setWfLogsError(null);
    setWfDiag(null);
    setWfProtocolWarnings([]);
    try {
      const result = await invoke<WebfilterLogsInvokeResult>(
        "fetch_webfilter_logs",
        { payload: { settings } },
      );
      const envelope = toWebfilterDynamicEnvelope<WfLogEntry>(result, new Date());

      if (envelope.statePatch.diag !== undefined) {
        setWfDiag(envelope.statePatch.diag);
      }

      if (envelope.warnings.length > 0) {
        const warningMessages = envelope.warnings.map((item) => item.message);
        setWfProtocolWarnings(warningMessages);
        setLogs((prev) => [...prev, ...warningMessages.map((item) => `Webfilter protocol warning: ${item}`)]);
      }

      for (const action of envelope.actions) {
        if (action.type === "set-filter") {
          setWfLogFilter(action.filter);
        } else if (action.type === "set-auto-refresh") {
          setWfAutoRefresh(action.enabled);
        } else if (action.type === "schedule-refetch") {
          if (wfScheduledRefetchRef.current !== null) {
            window.clearTimeout(wfScheduledRefetchRef.current);
          }
          wfScheduledRefetchRef.current = window.setTimeout(() => {
            if (!canRunSourceNow("webfilter-ui")) return;
            if (activeTab === "webfilter") {
              void handleFetchWfLogs();
            }
          }, action.delayMs);
        }
      }

      if (result.ok && envelope.statePatch.entries) {
        setWfLogs(envelope.statePatch.entries);
        setWfLastRefresh(envelope.statePatch.lastRefreshLabel ?? new Date().toLocaleTimeString());
        markSourceSuccess("webfilter-ui");
        const status = parseWebfilterStatus("ok", "webfilter-ui", "webfilter-80-1920");
        return { ok: true, status };
      } else {
        const status = parseWebfilterStatus(
          envelope.statePatch.error ?? "Unknown error",
          "webfilter-ui",
          "webfilter-80-1920",
        );
        markSourceError("webfilter-ui", status.message);
        scheduleSourceRetry("webfilter-ui");
        setWfLogsError(status.message);
        return { ok: false, status };
      }
    } catch (err) {
      const status = parseWebfilterStatus(String(err), "webfilter-ui", "webfilter-80-1920");
      markSourceError("webfilter-ui", status.message);
      scheduleSourceRetry("webfilter-ui");
      setWfLogsError(status.message);
      return { ok: false, status };
    } finally {
      setWfLogsBusy(false);
    }
  }

  async function handleFetchWfAddressLists() {
    setWfAddressBusy(true);
    setWfAddressError(null);
    try {
      const result = await invoke<WebfilterAddressListsInvokeResult>(
        "fetch_webfilter_address_lists",
        { payload: { settings } },
      );
      if (!result.ok) {
        const errorMessage = result.error ?? "Unknown error while loading address lists";
        setWfAddressError(errorMessage);
        markSourceError("webfilter-ui", errorMessage);
        scheduleSourceRetry("webfilter-ui");
        return;
      }

      const whitelist = result.whitelistEntries ?? [];
      const blacklist = result.blacklistEntries ?? [];

      setWfWhitelistEntries(whitelist);
      setWfBlacklistEntries(blacklist);
      setWfWhitelistTotal(result.whitelistTotal ?? whitelist.length);
      setWfBlacklistTotal(result.blacklistTotal ?? blacklist.length);
      setWfAddressSelectedIds((prev) => {
        const valid = new Set((wfAddressListType === "wl" ? whitelist : blacklist).map((item) => item.id));
        return new Set(Array.from(prev).filter((id) => valid.has(id)));
      });
      markSourceSuccess("webfilter-ui");
      setLogs((prev) => [
        ...prev,
        `Address lists loaded (WL: ${result.whitelistTotal ?? whitelist.length}, BL: ${result.blacklistTotal ?? blacklist.length}).`,
      ]);
    } catch (error) {
      const message = String(error);
      setWfAddressError(message);
      markSourceError("webfilter-ui", message);
      scheduleSourceRetry("webfilter-ui");
    } finally {
      setWfAddressBusy(false);
    }
  }

  async function handleWriteWfAddressList(
    action: "add" | "edit" | "delete" | "import" | "export",
    options?: {
      entryId?: string;
      entryName?: string;
      currentName?: string;
      entryIds?: string[];
      importText?: string;
      savePath?: string;
    },
  ) {
    setWfAddressActionBusy(true);
    setWfAddressError(null);
    try {
      const payload = {
        settings,
        action,
        listType: wfAddressListType,
        entryId: options?.entryId,
        entryName: options?.entryName,
        currentName: options?.currentName,
        entryIds: options?.entryIds ?? [],
        importText: options?.importText,
        savePath: options?.savePath,
      };

      const result = await invoke<WebfilterAddressListWriteInvokeResult>(
        "write_webfilter_address_list",
        { payload },
      );

      if (!result.ok) {
        const errorMessage = result.error ?? "Address list operation failed";
        setWfAddressError(errorMessage);
        markSourceError("webfilter-ui", errorMessage);
        scheduleSourceRetry("webfilter-ui");
        return false;
      }

      const warnings = result.warnings ?? [];
      if (warnings.length > 0) {
        setLogs((prev) => [...prev, ...warnings.map((item) => `Address-list warning: ${item}`)]);
      }
      if (result.message) {
        setLogs((prev) => [...prev, result.message as string]);
      }

      markSourceSuccess("webfilter-ui");
      if (action !== "export") {
        await handleFetchWfAddressLists();
      }
      return true;
    } catch (error) {
      const message = String(error);
      setWfAddressError(message);
      markSourceError("webfilter-ui", message);
      scheduleSourceRetry("webfilter-ui");
      return false;
    } finally {
      setWfAddressActionBusy(false);
    }
  }

  function toggleWfAddressSelection(entryId: string, checked: boolean) {
    setWfAddressSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) {
        next.add(entryId);
      } else {
        next.delete(entryId);
      }
      return next;
    });
  }

  function toggleWfAddressSelectAllVisible(checked: boolean) {
    setWfAddressSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) {
        wfAddressEntriesFiltered.forEach((entry) => next.add(entry.id));
      } else {
        wfAddressEntriesFiltered.forEach((entry) => next.delete(entry.id));
      }
      return next;
    });
  }

  async function handleWfAddressAdd() {
    const value = wfAddressNewValue.trim();
    if (!value) {
      setWfAddressError("Address value is empty.");
      return;
    }
    const ok = await handleWriteWfAddressList("add", { entryName: value });
    if (ok) {
      setWfAddressNewValue("");
    }
  }

  async function handleWfAddressEditSave() {
    if (!wfAddressEditId) {
      setWfAddressError("Select an entry to edit first.");
      return;
    }
    const value = wfAddressEditValue.trim();
    if (!value) {
      setWfAddressError("Edited value is empty.");
      return;
    }
    const ok = await handleWriteWfAddressList("edit", {
      entryId: wfAddressEditId,
      entryName: value,
      currentName: wfAddressEditOriginalName,
    });
    if (ok) {
      setWfAddressEditId(null);
      setWfAddressEditOriginalName("");
      setWfAddressEditValue("");
    }
  }

  async function handleWfAddressDeleteSelected() {
    const ids = wfAddressEntries
      .map((entry) => entry.id)
      .filter((id) => wfAddressSelectedIds.has(id));

    if (ids.length === 0) {
      setWfAddressError("No entries selected for deletion.");
      return;
    }

    const ok = await handleWriteWfAddressList("delete", { entryIds: ids });
    if (ok) {
      setWfAddressSelectedIds(new Set());
    }
  }

  async function handleWfAddressImport() {
    const importText = wfAddressImportText.trim();
    if (!importText) {
      setWfAddressError("Import text is empty.");
      return;
    }
    const ok = await handleWriteWfAddressList("import", { importText });
    if (ok) {
      setWfAddressImportText("");
    }
  }

  async function handleWfAddressExport() {
    const defaultPath = wfAddressListType === "wl" ? "webfilter_whitelist_export.txt" : "webfilter_blacklist_export.txt";
    const savePath = await save({
      title: "Save webfilter address list export",
      defaultPath,
    });
    if (!savePath) {
      setLogs((prev) => [...prev, "Address-list export canceled."]);
      return;
    }
    await handleWriteWfAddressList("export", { savePath });
  }

  async function handleRefreshAnalysis() {
    if (analysisRefreshBusy || dynamicBusy || staticRefreshBusy || wfLogsBusy) {
      setLogs((prev) => [...prev, "Analysis refresh already running. Please wait..."]);
      return;
    }

    setAnalysisRefreshBusy(true);
    setLogs((prev) => [...prev, "Refreshing analysis sources (leases + webfilter)..."]);
    try {
      await refreshLeasesSilently();
      if (settings.msdUsername.trim() && hasMsdPassword) {
        const wfResult = await handleFetchWfLogs();
        if (!wfResult.ok) {
          const recovery = wfResult.status.recoveryAction !== "None"
            ? ` Recovery: ${wfResult.status.recoveryAction}.`
            : "";
          setLogs((prev) => [
            ...prev,
            `Webfilter status (${wfResult.status.status}): ${wfResult.status.message}${recovery}`,
          ]);
        }
      }
    } finally {
      setAnalysisRefreshBusy(false);
    }
  }

  async function handleCancelRun() {
    if (cancelRequested) return;
    setCancelRequested(true);
    setLogs((prev) => [...prev, "Cancel requested..."]);
    try {
      await invoke("cancel_run");
    } catch (error) {
      setRunError(String(error));
      setCancelRequested(false);
    }
  }

  async function handleDetectPython() {
    setHelpBusy(true);
    try {
      const result = await invoke<HelpResult>("find_python");
      setHelpLogs(result.lines);
      if (result.value) {
        setSettings((prev) => ({ ...prev, pythonPath: result.value ?? prev.pythonPath }));
      }
    } catch (error) {
      setHelpLogs([`Detect Python failed: ${error}`]);
    } finally {
      setHelpBusy(false);
    }
  }

  async function handleInstallDeps() {
    setHelpBusy(true);
    try {
      const result = await invoke<HelpResult>("install_backend_deps", {
        pythonPath: settings.pythonPath,
      });
      setHelpLogs(result.lines);
    } catch (error) {
      setHelpLogs([`Install requirements failed: ${error}`]);
    } finally {
      setHelpBusy(false);
    }
  }

  function toggleAllAdds() {
    if (diff.adds.length === 0) return;
    if (allAddsChecked) {
      setExcludedAddKeys(new Set(diff.adds.map(rowKey)));
      return;
    }
    setExcludedAddKeys(new Set());
  }

  function toggleAllConflicts() {
    if (diff.conflicts.length === 0) return;
    if (allConflictsChecked) {
      setExcludedConflictKeys(new Set(diff.conflicts.map(({ incoming }) => rowKey(incoming))));
      return;
    }
    setExcludedConflictKeys(new Set());
  }

  function toggleAllDeletes() {
    if (deletableDeletes.length === 0) return;
    if (allDeletesChecked) {
      setSelectedDeleteKeys((prev) => {
        const next = new Set(prev);
        deletableDeletes.forEach((row) => next.delete(rowKey(row)));
        return next;
      });
      return;
    }
    setSelectedDeleteKeys((prev) => {
      const next = new Set(prev);
      deletableDeletes.forEach((row) => next.add(rowKey(row)));
      return next;
    });
  }

  function toggleAllAddsW() {
    if (diffW.adds.length === 0) return;
    if (allAddsCheckedW) { setExcludedAddKeysW(new Set(diffW.adds.map(rowKey))); return; }
    setExcludedAddKeysW(new Set());
  }

  function toggleAllConflictsW() {
    if (diffW.conflicts.length === 0) return;
    if (allConflictsCheckedW) {
      setExcludedConflictKeysW(new Set(diffW.conflicts.map(({ incoming: r }) => rowKey(r))));
      return;
    }
    setExcludedConflictKeysW(new Set());
  }

  function toggleAllDeletesW() {
    if (deletableDeletesW.length === 0) return;
    if (allDeletesCheckedW) {
      setSelectedDeleteKeysW((prev) => { const next = new Set(prev); deletableDeletesW.forEach((row) => next.delete(rowKey(row))); return next; });
      return;
    }
    setSelectedDeleteKeysW((prev) => { const next = new Set(prev); deletableDeletesW.forEach((row) => next.add(rowKey(row))); return next; });
  }

  function handleConflictToggle(incoming: ClientRow, existingRow: ClientRow) {
    const key = rowKey(incoming);
    const currentlyChecked = !excludedConflictKeys.has(key);
    if (currentlyChecked) {
      setExcludedConflictKeys((prev) => { const next = new Set(prev); next.add(key); return next; });
      return;
    }
    const secondary = findSecondaryConflict(incoming, existingRow);
    if (secondary) { setDeletePrompt({ incoming, existing: existingRow, conflict: secondary }); return; }
    setExcludedConflictKeys((prev) => { const next = new Set(prev); next.delete(key); return next; });
  }

  function handleConflictToggleW(incoming: ClientRow, existingRow: ClientRow) {
    const key = rowKey(incoming);
    const currentlyChecked = !excludedConflictKeysW.has(key);
    if (currentlyChecked) {
      setExcludedConflictKeysW((prev) => { const next = new Set(prev); next.add(key); return next; });
      return;
    }
    const secondary = findSecondaryConflictW(incoming, existingRow);
    if (secondary) { setDeletePromptW({ incoming, existing: existingRow, conflict: secondary }); return; }
    setExcludedConflictKeysW((prev) => { const next = new Set(prev); next.delete(key); return next; });
  }

  function confirmDeleteConflict() {
    if (!deletePrompt) return;
    const { incoming, conflict } = deletePrompt;
    const incomingKey = rowKey(incoming);
    const conflictKey = rowKey(conflict.row);
    setExcludedConflictKeys((prev) => { const next = new Set(prev); next.delete(incomingKey); return next; });
    setForcedDeleteRows((prev) => ({ ...prev, [conflictKey]: conflict.row }));
    setSelectedDeleteKeys((prev) => { const next = new Set(prev); next.add(conflictKey); return next; });
    setDeletePrompt(null);
  }

  function cancelDeleteConflict() {
    setDeletePrompt(null);
  }

  function confirmDeleteConflictW() {
    if (!deletePromptW) return;
    const { incoming, conflict } = deletePromptW;
    const incomingKey = rowKey(incoming);
    const conflictKey = rowKey(conflict.row);
    setExcludedConflictKeysW((prev) => { const next = new Set(prev); next.delete(incomingKey); return next; });
    setForcedDeleteRowsW((prev) => ({ ...prev, [conflictKey]: conflict.row }));
    setSelectedDeleteKeysW((prev) => { const next = new Set(prev); next.add(conflictKey); return next; });
    setDeletePromptW(null);
  }

  function cancelDeleteConflictW() {
    setDeletePromptW(null);
  }

  function applyBaseUrlCleanup() {
    if (!baseUrlCleanupPrompt) return;
    const next = suggestCleanedUrls(baseUrlCleanupPrompt.enteredBaseUrl);
    setSettings((prev) => ({ ...prev, ...next }));
    setBaseUrlCleanupPrompt(null);
  }

  function keepEnteredBaseUrl() {
    if (!baseUrlCleanupPrompt) return;
    const next = deriveUrlsFromBase(baseUrlCleanupPrompt.enteredBaseUrl);
    setSettings((prev) => ({ ...prev, ...next }));
    setBaseUrlCleanupPrompt(null);
  }

  function handleBaseUrlBlur() {
    const entered = settings.baseUrl;
    const enteredDerived = deriveUrlsFromBase(entered);
    const suggestedDerived = suggestCleanedUrls(entered);
    if (!enteredDerived.baseUrl) {
      setSettings((prev) => ({ ...prev, ...enteredDerived }));
      return;
    }
    if (suggestedDerived.baseUrl && suggestedDerived.baseUrl !== enteredDerived.baseUrl) {
      setBaseUrlCleanupPrompt({
        enteredBaseUrl: entered,
        suggestedBaseUrl: suggestedDerived.baseUrl,
      });
      return;
    }
    setSettings((prev) => ({ ...prev, ...enteredDerived }));
  }

  function openMoveDynamicPrompt(lease: DynamicLease) {
    setMoveDynamicPrompt({
      iface: lease.iface,
      ip: lease.ip,
      mac: lease.mac,
      hostname: lease.hostname,
    });
    setUpdateStaticIpSelected(true);
    setUpdateStaticMacSelected(true);
  }

  async function cancelMoveDynamicPrompt() {
    if (moveDynamicBusy) return;
    setMoveDynamicPrompt(null);
    setUpdateStaticIpSelected(true);
    setUpdateStaticMacSelected(true);
    await refreshLeasesSilently();
  }

  async function confirmMoveDynamicToStatic() {
    if (!moveDynamicPrompt) return;
    if (!canSubmitMoveDynamic) return;
    setMoveDynamicBusy(true);
    setDynamicError(null);
    try {
      setLogs((prev) => [...prev, "Preparing dynamic → static move..."]);
      const settingsForMove = await bootstrapApiDataIfNeeded(settings);
      setLogs((prev) => [...prev, "Refreshing static export for conflict precheck..."]);
      const precheckExport = await invoke<RunRecord>("export_static", { payload: { settings: settingsForMove } });
      if (precheckExport.exportCsv) {
        setExistingCsv(precheckExport.exportCsv);
      }
      const refreshedRows = parseCsv(precheckExport.exportCsv ?? "").rows;
      const precheck = evaluateMoveConflicts(refreshedRows, moveDynamicPrompt);
      if (precheck.alreadyExists || precheck.ipConflict || precheck.macConflict || precheck.nameConflict) {
        const messages: string[] = ["Move blocked by static-side conflict after refresh."];
        if (precheck.ipConflict) {
          messages.push(
            `IP already used by ${precheck.ipConflict.name} (${precheck.ipConflict.mac}).`
              + (precheck.suggestedIp ? ` Suggested free IP: ${precheck.suggestedIp}` : ""),
          );
        }
        if (precheck.nameConflict) {
          messages.push(
            `Hostname already used by ${precheck.nameConflict.mac} (${precheck.nameConflict.ip}).`
              + (precheck.suggestedName ? ` Suggested name: ${precheck.suggestedName}` : ""),
          );
        }
        if (precheck.macConflict) {
          messages.push(`MAC already exists on static IP ${precheck.macConflict.ip}.`);
        }
        if (precheck.alreadyExists) {
          messages.push("Lease already exists on static side.");
        }
        setDynamicError(messages.join(" "));
        setLogs((prev) => [...prev, ...messages]);
        return;
      }

      setLogs((prev) => [...prev, "Submitting move request to router..."]);
      const payload: MoveDynamicLeasePayload = {
        settings: settingsForMove,
        iface: moveDynamicPrompt.iface,
        ip: moveDynamicPrompt.ip,
        mac: moveDynamicPrompt.mac,
        hostname: moveDynamicPrompt.hostname,
      };
      const result = await invoke<MoveDynamicLeaseResult>("move_dynamic_to_static", { payload });
      if (!result.ok) {
        setDynamicError(result.message || result.status || "Move to static failed.");
        return;
      }
      const moveLine = `Moved dynamic lease to static: ${payload.hostname} ${payload.mac} ${payload.ip}`;
      setLogs((prev) => [...prev, moveLine]);
      const record: RunRecord = {
        timestamp: new Date().toISOString(),
        lines: ["Dynamic to static move", moveLine, `Status: ${result.status}`],
      };
      setHistory((prev) => [record, ...prev]);
      setMoveDynamicPrompt(null);
      setLogs((prev) => [...prev, "Refreshing dynamic leases after successful move..."]);
      await handleLoadDynamicLeases();
      setLogs((prev) => [...prev, "Refreshing static export after successful move..."]);
      await refreshStaticLeases();
      await refreshLeasesSilently();
    } catch (error) {
      setDynamicError(String(error));
    } finally {
      setMoveDynamicBusy(false);
    }
  }

  async function confirmUpdateStaticFromDynamic() {
    if (!moveDynamicPrompt || !moveConflictTarget) return;
    if (!moveDynamicIpValid || !moveDynamicMacValid || !moveDynamicNameValid) return;
    if (!updateStaticIpSelected && !updateStaticMacSelected) {
      setDynamicError("Select at least one field (IP or MAC) to update.");
      return;
    }
    setMoveDynamicBusy(true);
    setDynamicError(null);
    try {
      setLogs((prev) => [...prev, "Updating existing static lease with dynamic values..."]);
      const settingsForUpdate = await bootstrapApiDataIfNeeded(settings);
      const nextIp = updateStaticIpSelected ? moveDynamicPrompt.ip : moveConflictTarget.ip;
      const nextMac = updateStaticMacSelected ? moveDynamicPrompt.mac : moveConflictTarget.mac;
      const payload: UpdateStaticFromDynamicPayload = {
        settings: settingsForUpdate,
        oldMac: moveConflictTarget.mac,
        iface: moveDynamicPrompt.iface,
        ip: nextIp,
        mac: nextMac,
        hostname: moveConflictTarget.name,
      };
      const result = await invoke<UpdateStaticFromDynamicResult>("update_static_from_dynamic", { payload });
      if (!result.ok) {
        setDynamicError(result.message || result.status || "Static update failed.");
        return;
      }
      const updatedFields = [
        updateStaticIpSelected ? "IP" : null,
        updateStaticMacSelected ? "MAC" : null,
      ].filter(Boolean).join("+");
      const updateLine =
        `Updated static lease ${moveConflictTarget.name} (${moveConflictTarget.mac}) `
        + `[${updatedFields}] -> ${payload.mac} ${payload.ip}`;
      setLogs((prev) => [...prev, updateLine]);
      setHistory((prev) => [
        {
          timestamp: new Date().toISOString(),
          lines: ["Static lease update from dynamic", updateLine, `Status: ${result.status}`],
        },
        ...prev,
      ]);
      setMoveDynamicPrompt(null);
      setUpdateStaticIpSelected(true);
      setUpdateStaticMacSelected(true);
      setLogs((prev) => [...prev, "Refreshing dynamic/static data after static update..."]);
      await handleLoadDynamicLeases();
      const exportResult = await invoke<RunRecord>("export_static", { payload: { settings: settingsForUpdate } });
      setHistory((prev) => [exportResult, ...prev]);
      if (exportResult.exportCsv) {
        setExistingCsv(exportResult.exportCsv);
      }
      await refreshLeasesSilently();
    } catch (error) {
      setDynamicError(String(error));
    } finally {
      setMoveDynamicBusy(false);
    }
  }

  return (
    <div
      className={`app ${
        autoExporting ||
        autoExportPrompt ||
        isRunning ||
        showUpdateOverlay ||
        baseUrlCleanupPrompt ||
        moveDynamicPrompt ||
        deletePromptW
          ? "app-busy"
          : ""
      }`}
    >
      {moveDynamicPrompt && (
        <div className="overlay" aria-live="polite" aria-busy="true">
          <div className="overlay-card move-overlay-card">
            <div className="overlay-title">Move dynamic lease to static?</div>
            <div className="overlay-subtitle">Supported interfaces: Gruen (LAN) and WLANBYOD (opt4).</div>
            <div className="move-lease-grid">
              <div className="move-lease-box">
                <span className="move-lease-label">Interface</span>
                <strong>{moveDynamicPrompt.iface}</strong>
              </div>
              <div className="move-lease-box">
                <span className="move-lease-label">Dynamic MAC</span>
                <strong>{moveDynamicPrompt.mac}</strong>
              </div>
            </div>
            <div className="field">
              <label htmlFor="move-dynamic-host">Hostname</label>
              <input
                id="move-dynamic-host"
                type="text"
                value={moveDynamicPrompt.hostname}
                onChange={(e) =>
                  setMoveDynamicPrompt((prev) => (prev ? { ...prev, hostname: e.currentTarget.value } : prev))
                }
                disabled={moveDynamicBusy}
              />
            </div>
            <div className="field">
              <label htmlFor="move-dynamic-ip">IP address</label>
              <input
                id="move-dynamic-ip"
                type="text"
                value={moveDynamicPrompt.ip}
                onChange={(e) =>
                  setMoveDynamicPrompt((prev) => (prev ? { ...prev, ip: e.currentTarget.value } : prev))
                }
                disabled={moveDynamicBusy}
              />
            </div>

            {moveConflictTarget && (
              <div className="move-conflict-wrap">
                <div className="overlay-subtitle">Hostname/IP already used by static lease:</div>
                <div className="move-lease-grid">
                  <div className="move-lease-box">
                    <span className="move-lease-label">Name</span>
                    <strong>{moveConflictTarget.name}</strong>
                  </div>
                  <div className="move-lease-box">
                    <span className="move-lease-label">IP</span>
                    <strong>{moveConflictTarget.ip}</strong>
                  </div>
                  <div className="move-lease-box">
                    <span className="move-lease-label">MAC</span>
                    <strong>{moveConflictTarget.mac}</strong>
                  </div>
                </div>
                <div className="move-update-options">
                  <label className="toggle-pill">
                    <input
                      type="checkbox"
                      checked={updateStaticIpSelected}
                      onChange={(e) => setUpdateStaticIpSelected(e.currentTarget.checked)}
                      disabled={moveDynamicBusy}
                    />
                    Update IP
                  </label>
                  <label className="toggle-pill">
                    <input
                      type="checkbox"
                      checked={updateStaticMacSelected}
                      onChange={(e) => setUpdateStaticMacSelected(e.currentTarget.checked)}
                      disabled={moveDynamicBusy}
                    />
                    Update MAC
                  </label>
                </div>
                <div className="overlay-actions">
                  <button
                    className="secondary"
                    type="button"
                    onClick={confirmUpdateStaticFromDynamic}
                    disabled={
                      moveDynamicBusy ||
                      !moveDynamicIpValid ||
                      !moveDynamicMacValid ||
                      !moveDynamicNameValid ||
                      (!updateStaticIpSelected && !updateStaticMacSelected)
                    }
                  >
                    Update static entry with dynamic IP/MAC
                  </button>
                </div>
              </div>
            )}

            {!moveDynamicIpValid && <div className="overlay-subtitle">Enter a valid IPv4 address.</div>}
            {!moveDynamicMacValid && <div className="overlay-subtitle">Invalid MAC address format.</div>}
            {!moveDynamicNameValid && <div className="overlay-subtitle">Hostname is required.</div>}
            {moveConflicts?.alreadyExists && (
              <div className="overlay-subtitle">This lease already exists on the static side.</div>
            )}
            {moveConflicts?.suggestedIp && (
              <div className="overlay-actions">
                <button
                  className="secondary"
                  type="button"
                  disabled={moveDynamicBusy}
                  onClick={() =>
                    setMoveDynamicPrompt((prev) =>
                      prev ? { ...prev, ip: moveConflicts.suggestedIp ?? prev.ip } : prev,
                    )
                  }
                >
                  Use suggested IP {moveConflicts.suggestedIp}
                </button>
              </div>
            )}
            {moveConflicts?.suggestedName && (
              <div className="overlay-actions">
                <button
                  className="secondary"
                  type="button"
                  disabled={moveDynamicBusy}
                  onClick={() =>
                    setMoveDynamicPrompt((prev) =>
                      prev ? { ...prev, hostname: moveConflicts.suggestedName ?? prev.hostname } : prev,
                    )
                  }
                >
                  Use suggested name {moveConflicts.suggestedName}
                </button>
              </div>
            )}
            {moveConflicts?.macConflict && (
              <div className="overlay-subtitle">
                MAC conflict with static lease: {moveConflicts.macConflict.name} · {moveConflicts.macConflict.ip}
              </div>
            )}
            <div className="overlay-actions">
              <button
                className="primary"
                type="button"
                onClick={confirmMoveDynamicToStatic}
                disabled={moveDynamicBusy || !canSubmitMoveDynamic}
              >
                {moveDynamicBusy ? "Moving..." : "Move to static"}
              </button>
              <button className="secondary" type="button" onClick={() => void cancelMoveDynamicPrompt()} disabled={moveDynamicBusy}>
                Cancel
              </button>
            </div>
            {dynamicError && <p className="error-text">{dynamicError}</p>}
          </div>
        </div>
      )}
      {baseUrlCleanupPrompt && (
        <div className="overlay" aria-live="polite" aria-busy="true">
          <div className="overlay-card">
            <div className="overlay-title">Clean Base URL?</div>
            <div className="overlay-subtitle">
              Suggested: {baseUrlCleanupPrompt.suggestedBaseUrl}
            </div>
            <div className="overlay-actions">
              <button className="primary" type="button" onClick={applyBaseUrlCleanup}>
                Apply cleanup
              </button>
              <button className="secondary" type="button" onClick={keepEnteredBaseUrl}>
                Keep entered value
              </button>
            </div>
          </div>
        </div>
      )}
      {(autoExporting || autoExportPrompt) && (
        <div className="overlay" aria-live="polite" aria-busy="true">
          <div className="overlay-card">
            <div className="overlay-title">Fetch static DHCP list?</div>
            <div className="overlay-subtitle">
              {autoExporting
                ? "Fetching now. Please wait."
                : "We can fetch the current static list in the background."}
            </div>
            {!autoExporting && (
              <div className="overlay-actions">
                <button className="primary" type="button" onClick={handleAutoExportConfirm}>
                  Fetch list
                </button>
                <button className="secondary" type="button" onClick={handleAutoExportCancel}>
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>
      )}
      {deletePrompt && (
        <div className="overlay" aria-live="polite" aria-busy="true">
          <div className="overlay-card">
            <div className="overlay-title">Delete conflicting lease?</div>
            <div className="overlay-subtitle">
              The update for {deletePrompt.incoming.name} will reuse the same {deletePrompt.conflict.field.toUpperCase()}.
              Delete the existing lease first?
            </div>
            <div className="overlay-actions">
              <button className="primary" type="button" onClick={confirmDeleteConflict}>
                Delete and continue
              </button>
              <button className="secondary" type="button" onClick={cancelDeleteConflict}>
                Cancel
              </button>
            </div>
            <div className="overlay-subtitle">
              Existing: {deletePrompt.conflict.row.name} · {deletePrompt.conflict.row.mac} · {deletePrompt.conflict.row.ip}
            </div>
          </div>
        </div>
      )}
      {deletePromptW && (
        <div className="overlay" aria-live="polite" aria-busy="true">
          <div className="overlay-card">
            <div className="overlay-title">Delete conflicting WLANBYOD lease?</div>
            <div className="overlay-subtitle">
              The update for {deletePromptW.incoming.name} will reuse the same {deletePromptW.conflict.field.toUpperCase()}.
              Delete the existing lease first?
            </div>
            <div className="overlay-actions">
              <button className="primary" type="button" onClick={confirmDeleteConflictW}>
                Delete and continue
              </button>
              <button className="secondary" type="button" onClick={cancelDeleteConflictW}>
                Cancel
              </button>
            </div>
            <div className="overlay-subtitle">
              Existing: {deletePromptW.conflict.row.name} · {deletePromptW.conflict.row.mac} · {deletePromptW.conflict.row.ip}
            </div>
          </div>
        </div>
      )}
      {showUpdateOverlay && (
        <div className="overlay" aria-live="polite" aria-busy="true">
          <div className="overlay-card run-overlay-card">
            <div className="overlay-title">
              {updateInfo?.version ? `Update available: v${updateInfo.version}` : "Update available"}
            </div>
            <div className="overlay-subtitle">
              {updateInstalling
                ? "Downloading and installing the update. The app will restart."
                : "A new version is available on GitHub."}
            </div>
            {!updateInstalling && (
              <div className="overlay-actions">
                <button className="primary" type="button" onClick={installUpdate} disabled={updateBusy}>
                  Install update
                </button>
                <button
                  className="secondary"
                  type="button"
                  onClick={() => setShowUpdatePrompt(false)}
                  disabled={updateBusy}
                >
                  Later
                </button>
              </div>
            )}
          </div>
        </div>
      )}
      {showRunOverlay && (
        <div className="overlay run-overlay" aria-live="polite" aria-busy="true">
          <div className="overlay-card run-overlay-card">
            <div className="overlay-title">{runOverlayTitle}</div>
            <div className="overlay-subtitle">Live log output</div>
            <pre className="run-overlay-log">{logs.join("\n") || "Starting..."}</pre>
            <div className="overlay-actions">
              <button
                className="secondary"
                type="button"
                onClick={handleCancelRun}
                disabled={cancelRequested}
              >
                {cancelRequested ? "Canceling..." : "Cancel"}
              </button>
            </div>
          </div>
        </div>
      )}
      {selectedAnalysisDeviceDetail && (
        <div
          className="overlay analysis-device-overlay"
          role="dialog"
          aria-modal="true"
          aria-label={`Device details for ${selectedAnalysisDeviceDetail.row.ip}`}
          onClick={() => setSelectedAnalysisDeviceIp(null)}
        >
          <div className="overlay-card analysis-device-overlay-card" onClick={(e) => e.stopPropagation()}>
            <div className="analysis-detail-head">
              <h4>Device Detail: {selectedAnalysisDeviceDetail.row.ip}</h4>
              <button className="mini-action" type="button" onClick={() => setSelectedAnalysisDeviceIp(null)}>
                Close
              </button>
            </div>
            <div className="analysis-detail-grid">
              <div className="analysis-detail-card">
                <h5>Identity</h5>
                <p>Hostname: {selectedAnalysisDeviceDetail.row.hostname || "-"}</p>
                <p>MAC: {selectedAnalysisDeviceDetail.row.mac || "-"}</p>
                <p>Segment: {selectedAnalysisDeviceDetail.row.segment}</p>
                <p>Risk: {selectedAnalysisDeviceDetail.row.riskScore}</p>
                <p>Last seen: {selectedAnalysisDeviceDetail.row.lastSeen || "-"}</p>
              </div>
              <div className="analysis-detail-card">
                <h5>Lease Times</h5>
                <p>Static lease: {selectedAnalysisDeviceDetail.staticLease ? "Yes" : "No"}</p>
                <p>Dynamic online: {selectedAnalysisDeviceDetail.dynamicLease ? (selectedAnalysisDeviceDetail.dynamicLease.online ? "Yes" : "No") : "-"}</p>
                <p>Dynamic start: {selectedAnalysisDeviceDetail.dynamicLease?.start || "-"}</p>
                <p>Dynamic end: {selectedAnalysisDeviceDetail.dynamicLease?.end || "-"}</p>
                <p>Dynamic status: {selectedAnalysisDeviceDetail.dynamicLease?.status || "-"}</p>
              </div>
              <div className="analysis-detail-card">
                <h5>Traffic Summary</h5>
                <p>Firewall pass/block: {selectedAnalysisDeviceDetail.row.fwPass} / {selectedAnalysisDeviceDetail.row.fwBlock}</p>
                <p>Webfilter allow/block: {selectedAnalysisDeviceDetail.row.wfAllow} / {selectedAnalysisDeviceDetail.row.wfBlock}</p>
                <p>Dual block: {selectedAnalysisDeviceDetail.row.hasDualBlock ? "Yes" : "No"}</p>
              </div>
            </div>

            <div className="analysis-detail-grid">
              <div className="analysis-detail-card">
                <h5>Visited Pages (Webfilter)</h5>
                <ul className="analysis-detail-list">
                  {selectedAnalysisDeviceDetail.webfilterEvents.map((event, idx) => (
                    <li key={`detail-wf-${idx}`}>
                      <span>{event.time || "-"}</span>
                      <strong>{event.action.toUpperCase()}</strong>
                      <span>{event.url || "-"}</span>
                      <span>{event.category || "-"}</span>
                    </li>
                  ))}
                  {selectedAnalysisDeviceDetail.webfilterEvents.length === 0 && (
                    <li>No webfilter events recorded for this device.</li>
                  )}
                </ul>
              </div>
              <div className="analysis-detail-card">
                <h5>Firewall Events</h5>
                <ul className="analysis-detail-list">
                  {selectedAnalysisDeviceDetail.firewallEvents.map((event, idx) => (
                    <li key={`detail-fw-${idx}`}>
                      <span>{event.__timestamp__ || "-"}</span>
                      <strong>{event.action || "-"}</strong>
                      <span>{`${event.src || "-"} -> ${event.dst || "-"}`}</span>
                      <span>{event.label || "-"}</span>
                    </li>
                  ))}
                  {selectedAnalysisDeviceDetail.firewallEvents.length === 0 && (
                    <li>No firewall events recorded for this device.</li>
                  )}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
      <div className="app-content">
        <header className="topbar">
        <div>
          <p className="eyebrow">TFK Manager</p>
          <h1>DHCP Lease Manager</h1>
          <p className="subhead">Manage static and dynamic leases with validation, conflict checks, and guided change workflows.</p>
        </div>
        <div className="status-card">
          <span>Version</span>
          <strong>{appVersion ? `v${appVersion}` : "v-"}</strong>
        </div>
      </header>

      <div className="layout">
        <aside className="panel settings">
          <div className="tab-group">
            <button
              type="button"
              className={activeTab === "leases" ? "active" : ""}
              onClick={() => setActiveTab("leases")}
            >
              Leases
            </button>
            <button
              type="button"
              className={activeTab === "settings" ? "active" : ""}
              onClick={() => setActiveTab("settings")}
            >
              Settings
            </button>
            <button
              type="button"
              className={activeTab === "history" ? "active" : ""}
              onClick={() => setActiveTab("history")}
            >
              History
            </button>
            <button
              type="button"
              className={activeTab === "help" ? "active" : ""}
              onClick={() => setActiveTab("help")}
            >
              Help
            </button>
            <button
              type="button"
              className={activeTab === "firewall" ? "active" : ""}
              onClick={() => setActiveTab("firewall")}
            >
              Firewall
            </button>
            <button
              type="button"
              className={activeTab === "webfilter" ? "active" : ""}
              onClick={() => setActiveTab("webfilter")}
            >
              Webfilter
            </button>
            <button
              type="button"
              className={activeTab === "analysis" ? "active" : ""}
              onClick={() => setActiveTab("analysis")}
            >
              Analysis
            </button>
          </div>

          {activeTab === "leases" && (
            <div className="tab-panel">
              <h2>Lease Inputs</h2>
              <div className="lease-view-tabs">
                <button
                  type="button"
                  className={leaseView === "static" ? "active" : ""}
                  onClick={() => setLeaseView("static")}
                >
                  Static Gruen
                </button>
                <button
                  type="button"
                  className={leaseView === "staticWlanbyod" ? "active" : ""}
                  onClick={() => setLeaseView("staticWlanbyod")}
                >
                  Static WLANBYOD
                </button>
                <button
                  type="button"
                  className={leaseView === "dynamic" ? "active" : ""}
                  onClick={() => setLeaseView("dynamic")}
                >
                  Dynamic
                </button>
                <button
                  type="button"
                  className={leaseView === "review" ? "active" : ""}
                  onClick={() => setLeaseView("review")}
                >
                  Review
                </button>
                <button
                  type="button"
                  className={leaseView === "runlog" ? "active" : ""}
                  onClick={() => setLeaseView("runlog")}
                >
                  Run Log
                </button>
              </div>

              {leaseView === "static" ? (
                <>
                  <div className="field">
                    <label>Import incoming CSV</label>
                    <button className="secondary" type="button" onClick={() => void handlePickCsv("incoming")}>
                      Choose incoming CSV
                    </button>
                  </div>
                  <div className="field">
                    <label>Import existing export CSV</label>
                    <button className="secondary" type="button" onClick={() => void handlePickCsv("existing")}>
                      Choose existing CSV
                    </button>
                  </div>
                  <div className="field">
                    <label>Paste incoming CSV</label>
                    <textarea
                      value={incomingCsv}
                      onChange={(e) => setIncomingCsv(e.currentTarget.value)}
                      placeholder="Name;Raum;IP;MAC;Besitzer;Inventarnummer;Beschreibung"
                    />
                  </div>
                  <div className="field">
                    <label>Paste existing export CSV</label>
                    <textarea
                      value={existingCsv}
                      onChange={(e) => setExistingCsv(e.currentTarget.value)}
                      placeholder="Name;MAC;IP"
                    />
                  </div>
                </>
              ) : leaseView === "staticWlanbyod" ? (
                <>
                  <div className="field">
                    <label>Import incoming CSV (WLANBYOD)</label>
                    <button className="secondary" type="button" onClick={() => void handlePickCsvW("incoming")}>
                      Choose incoming CSV
                    </button>
                  </div>
                  <div className="field">
                    <label>Import existing export CSV (WLANBYOD)</label>
                    <button className="secondary" type="button" onClick={() => void handlePickCsvW("existing")}>
                      Choose existing CSV
                    </button>
                  </div>
                  <div className="field">
                    <label>Paste incoming CSV (WLANBYOD)</label>
                    <textarea
                      value={incomingCsvW}
                      onChange={(e) => setIncomingCsvW(e.currentTarget.value)}
                      placeholder="Name;Raum;IP;MAC;Besitzer;Inventarnummer;Beschreibung"
                    />
                  </div>
                  <div className="field">
                    <label>Paste existing export CSV (WLANBYOD)</label>
                    <textarea
                      value={existingCsvW}
                      onChange={(e) => setExistingCsvW(e.currentTarget.value)}
                      placeholder="Name;MAC;IP"
                    />
                  </div>
                </>
              ) : (
                <p className="lease-meta">CSV import/edit is available in Static view.</p>
              )}
            </div>
          )}

          {activeTab === "settings" && (
            <div className="tab-panel">
              <h2>Settings</h2>
              <div className="field">
                <label htmlFor="base-url">Base URL</label>
                <input
                  id="base-url"
                  type="text"
                  value={settings.baseUrl}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, baseUrl: value }));
                  }}
                  onBlur={handleBaseUrlBlur}
                />
              </div>
              <div className="field">
                <label htmlFor="python-path">Python path</label>
                <input
                  id="python-path"
                  type="text"
                  value={settings.pythonPath}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, pythonPath: value }));
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="login-url">Login URL</label>
                <input
                  id="login-url"
                  type="text"
                  value={settings.loginUrl}
                  readOnly
                />
              </div>
              <div className="field">
                <label htmlFor="username">Username</label>
                <input
                  id="username"
                  type="text"
                  value={settings.username}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, username: value }));
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.currentTarget.value)}
                  placeholder={hasPassword ? "Saved. Enter new to replace." : "Enter to save securely"}
                />
              </div>
              <div className="field">
                <label htmlFor="dashboard-url">Dashboard URL</label>
                <input
                  id="dashboard-url"
                  type="text"
                  value={settings.dashboardUrl}
                  readOnly
                />
              </div>
              <div className="field">
                <label htmlFor="api-username">API username</label>
                <input
                  id="api-username"
                  type="text"
                  value={settings.apiUsername}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, apiUsername: value }));
                  }}
                  placeholder="Auto-filled from /api/tfk/dhcp/apiuserinformation"
                />
              </div>
              <div className="field">
                <label htmlFor="api-key">API key</label>
                <input
                  id="api-key"
                  type="text"
                  value={settings.apiKey}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, apiKey: value }));
                  }}
                  placeholder="Auto-filled from /api/tfk/dhcp/apiuserinformation"
                />
              </div>
              <div className="field">
                <label htmlFor="api-secret">API secret</label>
                <input
                  id="api-secret"
                  type="text"
                  value={settings.apiSecret}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, apiSecret: value }));
                  }}
                  placeholder="Auto-filled from /api/tfk/dhcp/apiuserinformation"
                />
              </div>
              <div className="field">
                <label htmlFor="cookie-header">Cookie header (optional)</label>
                <input
                  id="cookie-header"
                  type="text"
                  value={settings.cookieHeader}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, cookieHeader: value }));
                  }}
                  placeholder="cookie_test=...; MSD_Cookie=...; PHPSESSID=..."
                />
              </div>
              <div className="field">
                <label htmlFor="msd-username">MSD username (Webfilter, port 80)</label>
                <input
                  id="msd-username"
                  type="text"
                  value={settings.msdUsername}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, msdUsername: value }));
                  }}
                  placeholder="e.g. soeren.schroeder"
                />
              </div>
              <div className="field">
                <label htmlFor="msd-password">MSD password (Webfilter, port 80)</label>
                <input
                  id="msd-password"
                  type="password"
                  value={msdPasswordInput}
                  onChange={(e) => setMsdPasswordInput(e.currentTarget.value)}
                  placeholder={hasMsdPassword ? "Saved. Enter new to replace." : "Enter to save securely"}
                />
              </div>
              <div className="field">
                <label htmlFor="debug-toggle">Debug logging</label>
                <label className="toggle-pill">
                  <input
                    id="debug-toggle"
                    type="checkbox"
                    checked={settings.debug}
                    onChange={(e) => {
                      const checked = e.currentTarget.checked;
                      setSettings((prev) => ({ ...prev, debug: checked }));
                    }}
                  />
                  Enable verbose backend logs
                </label>
              </div>
              <button className="secondary" type="button" onClick={handleSaveSettings}>
                Save settings
              </button>
            </div>
          )}

          {activeTab === "history" && (
            <div className="tab-panel">
              <h2>History</h2>
              <div className="history-list">
                {history.length === 0 && <p>No runs recorded yet.</p>}
                {history.map((entry, index) => (
                  <button
                    key={`hist-${index}`}
                    type="button"
                    className="history-item"
                    onClick={() => setLogs(entry.lines)}
                  >
                    <span>Run {history.length - index}</span>
                    <span>{new Date(entry.timestamp).toLocaleString()}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {activeTab === "help" && (
            <div className="tab-panel help-panel">
              <h2>Help & Setup</h2>
              <p className="help-lead">
                This app uses authenticated API calls via backend session cookies. Use the buttons below to prepare Python and dependencies.
              </p>
              <div className="help-section">
                <h3>1) Detect Python</h3>
                <p>Find a Python executable and update the Settings automatically.</p>
                <button className="secondary" type="button" onClick={handleDetectPython} disabled={helpBusy}>
                  {helpBusy ? "Working..." : "Detect Python"}
                </button>
              </div>
              <div className="help-section">
                <h3>2) Install requirements</h3>
                <p>Install backend dependencies from requirements.txt.</p>
                <button className="secondary" type="button" onClick={handleInstallDeps} disabled={helpBusy}>
                  {helpBusy ? "Working..." : "Install requirements"}
                </button>
              </div>
              <div className="help-section">
                <h3>Checklist</h3>
                <ul className="help-list">
                  <li>Enter OPNsense URLs and username in Settings.</li>
                  <li>Save a password in Settings (stored securely).</li>
                  <li>Optional: paste Cookie header from browser DevTools for session reuse.</li>
                  <li>Import or paste your incoming and existing CSVs.</li>
                </ul>
              </div>
              <div className="help-section">
                <h3>Updates</h3>
                <p>Check GitHub for new releases and install if available.</p>
                <button
                  className="secondary"
                  type="button"
                  onClick={() => checkForUpdates()}
                  disabled={updateBusy || updateInstalling}
                >
                  {updateBusy ? "Checking..." : "Check for updates"}
                </button>
                {updateStatus && <p className="help-update">{updateStatus}</p>}
              </div>
              <div className="help-log">
                <h3>Setup log</h3>
                <pre>{helpLogs.join("\n") || "No setup actions yet."}</pre>
              </div>
            </div>
          )}

          {activeTab === "firewall" && (
            <div className="tab-panel">
              <h2>Firewall Log</h2>
              <div className="fw-sidebar-controls">
                <div className="fw-stream-status">
                  {fwStreaming && <span className="fw-live-dot" />}
                  <span>{fwStreaming ? "Live" : "Stopped"}</span>
                </div>
                <button
                  className={fwStreaming ? "secondary" : "primary"}
                  type="button"
                  onClick={fwStreaming ? handleStopFwLog : () => void handleStartFwLog()}
                >
                  {fwStreaming ? "Stop" : "Start"}
                </button>
                <button
                  className="secondary"
                  type="button"
                  onClick={() => setFwLogs([])}
                >
                  Clear
                </button>
              </div>
              <div className="fw-filter-tabs">
                {(["all", "pass", "block", "rdr"] as const).map((f) => (
                  <button
                    key={f}
                    type="button"
                    className={fwFilter === f ? "active" : ""}
                    onClick={() => setFwFilter(f)}
                  >
                    {f === "all" ? "All" : f === "pass" ? "Passed" : f === "block" ? "Blocked" : "Redirect"}
                  </button>
                ))}
              </div>
              <p className="lease-meta">
                {fwLogsFiltered.length} of {fwLogs.length} entries
                {fwLogs.length === MAX_FW_LOG_ENTRIES ? " (max — oldest removed)" : ""}
              </p>
              {fwError && <p className="error-text">{fwError}</p>}
            </div>
          )}

          {activeTab === "webfilter" && (
            <div className="tab-panel">
              <h2>Webfilter</h2>
              <p className="field-hint">
                Schulfilter Plus filter logs. Configure MSD credentials in Settings first.
              </p>
              <div className="wf-filter-tabs" style={{ marginBottom: "8px" }}>
                <button
                  type="button"
                  className={wfView === "logs" ? "active" : ""}
                  onClick={() => setWfView("logs")}
                >
                  Logs
                </button>
                <button
                  type="button"
                  className={wfView === "address-lists" ? "active" : ""}
                  onClick={() => setWfView("address-lists")}
                >
                  Address Lists
                </button>
              </div>
              {(!settings.msdUsername.trim() || !hasMsdPassword) ? (
                <p className="error-text" style={{ fontSize: "0.85rem" }}>
                  {!settings.msdUsername.trim() ? "Set MSD username in Settings." : "Set MSD password in Settings."}
                </p>
              ) : (
                <>
                  {wfView === "logs" ? (
                    <>
                      <button
                        type="button"
                        className="primary"
                        disabled={wfLogsBusy}
                        onClick={() => void handleFetchWfLogs()}
                        style={{ width: "100%", marginBottom: "8px" }}
                      >
                        {wfLogsBusy ? "Loading…" : "Fetch Logs"}
                      </button>
                      <label className="field-hint" style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "8px", cursor: "pointer" }}>
                        <input
                          type="checkbox"
                          checked={wfAutoRefresh}
                          onChange={(e) => setWfAutoRefresh(e.target.checked)}
                        />
                        Auto-refresh
                      </label>
                      <div className="wf-filter-tabs">
                        {(["all", "allow", "block"] as const).map((f) => (
                          <button
                            key={f}
                            type="button"
                            className={wfLogFilter === f ? "active" : ""}
                            onClick={() => setWfLogFilter(f)}
                          >
                            {f.charAt(0).toUpperCase() + f.slice(1)}
                          </button>
                        ))}
                      </div>
                      {wfLogsError && (
                        <p className="error-text" style={{ fontSize: "0.82rem" }}>{wfLogsError}</p>
                      )}
                      {wfProtocolWarnings.length > 0 && (
                        <ul className="wf-protocol-warning-list">
                          {wfProtocolWarnings.map((warning, idx) => (
                            <li key={`wf-warning-${idx}`}>{warning}</li>
                          ))}
                        </ul>
                      )}
                      {wfLastRefresh && (
                        <p className="field-hint">Last: {wfLastRefresh} · {wfLogsFiltered.length} entries</p>
                      )}
                    </>
                  ) : (
                    <>
                      <div className="wf-filter-tabs" style={{ marginBottom: "8px" }}>
                        <button
                          type="button"
                          className={wfAddressListType === "wl" ? "active" : ""}
                          onClick={() => setWfAddressListType("wl")}
                        >
                          Whitelist
                        </button>
                        <button
                          type="button"
                          className={wfAddressListType === "bl" ? "active" : ""}
                          onClick={() => setWfAddressListType("bl")}
                        >
                          Blacklist
                        </button>
                      </div>
                      <button
                        type="button"
                        className="primary"
                        disabled={wfAddressBusy || wfAddressActionBusy}
                        onClick={() => void handleFetchWfAddressLists()}
                        style={{ width: "100%", marginBottom: "8px" }}
                      >
                        {wfAddressBusy ? "Loading…" : "Refresh Address Lists"}
                      </button>
                      <div className="field" style={{ marginBottom: "10px" }}>
                        <label htmlFor="wf-address-new">Add Entry</label>
                        <input
                          id="wf-address-new"
                          type="text"
                          value={wfAddressNewValue}
                          onChange={(e) => setWfAddressNewValue(e.target.value)}
                          placeholder="example.com or *.example.*"
                          disabled={wfAddressActionBusy}
                        />
                      </div>
                      <button
                        type="button"
                        className="secondary"
                        disabled={wfAddressActionBusy}
                        onClick={() => void handleWfAddressAdd()}
                        style={{ width: "100%", marginBottom: "8px" }}
                      >
                        Add to {wfAddressListType === "wl" ? "Whitelist" : "Blacklist"}
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        disabled={wfAddressActionBusy || wfSelectedCount === 0}
                        onClick={() => void handleWfAddressDeleteSelected()}
                        style={{ width: "100%", marginBottom: "8px" }}
                      >
                        Delete Selected ({wfSelectedCount})
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        disabled={wfAddressActionBusy}
                        onClick={() => void handleWfAddressExport()}
                        style={{ width: "100%", marginBottom: "8px" }}
                      >
                        Export Current List
                      </button>
                      <div className="field" style={{ marginBottom: "8px" }}>
                        <label htmlFor="wf-address-import">Import Entries (one per line)</label>
                        <textarea
                          id="wf-address-import"
                          value={wfAddressImportText}
                          onChange={(e) => setWfAddressImportText(e.target.value)}
                          placeholder="domain1.example&#10;*.domain2.example"
                          disabled={wfAddressActionBusy}
                          style={{ minHeight: "90px" }}
                        />
                      </div>
                      <button
                        type="button"
                        className="secondary"
                        disabled={wfAddressActionBusy}
                        onClick={() => void handleWfAddressImport()}
                        style={{ width: "100%", marginBottom: "8px" }}
                      >
                        Import
                      </button>
                      {(wfAddressError || wfAddressEditId) && (
                        <div style={{ marginTop: "8px" }}>
                          {wfAddressError && <p className="error-text" style={{ fontSize: "0.82rem" }}>{wfAddressError}</p>}
                          {wfAddressEditId && (
                            <div className="field" style={{ marginBottom: "0" }}>
                              <label htmlFor="wf-address-edit">Edit Selected Entry</label>
                              <input
                                id="wf-address-edit"
                                type="text"
                                value={wfAddressEditValue}
                                onChange={(e) => setWfAddressEditValue(e.target.value)}
                                disabled={wfAddressActionBusy}
                              />
                              <button
                                type="button"
                                className="secondary"
                                disabled={wfAddressActionBusy}
                                onClick={() => void handleWfAddressEditSave()}
                              >
                                Save Edit
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                      <p className="field-hint">Loaded: {wfAddressEntries.length} visible entries · total reported: {wfAddressTotal}</p>
                    </>
                  )}
                  {settings.debug && wfDiag && (
                    <pre style={{ fontSize: "0.7rem", color: "#7a9e9a", whiteSpace: "pre-wrap", marginTop: "8px", background: "rgba(0,0,0,0.2)", padding: "6px", borderRadius: "4px", maxHeight: "200px", overflowY: "auto" }}>{wfDiag}</pre>
                  )}
                </>
              )}
            </div>
          )}

          {activeTab === "analysis" && (
            <div className="tab-panel">
              <h2>Combined Analysis</h2>
              <p className="field-hint">
                Correlates static and dynamic leases with firewall stream and webfilter events.
              </p>
              <div className="fw-sidebar-controls">
                <button
                  className="secondary"
                  type="button"
                  onClick={() => void handleRefreshAnalysis()}
                  disabled={analysisRefreshBusy || dynamicBusy || staticRefreshBusy || wfLogsBusy}
                >
                  {analysisRefreshBusy ? "Refreshing analysis sources..." : "Refresh analysis sources"}
                </button>
                <button
                  className={fwStreaming ? "secondary" : "primary"}
                  type="button"
                  onClick={fwStreaming ? handleStopFwLog : () => void handleStartFwLog()}
                >
                  {fwStreaming ? "Stop firewall stream" : "Start firewall stream"}
                </button>
              </div>
              <p className="lease-meta">
                Known devices: {analysis.knownDeviceCount} · Correlated active: {analysis.rows.length}
              </p>
              <div className="source-health-grid">
                {sourceHealthViews.map((item) => (
                  <div key={item.key} className={`source-health-card source-health-${item.status}`}>
                    <strong>{item.label}</strong>
                    <span>Status: {item.status}</span>
                    <span>Last success: {item.lastSuccessLabel}</span>
                    <span>{item.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </aside>

        <section className="panel main">

          {activeTab === "firewall" && (
            <div className="card full">
              <div className="preview-header">
                <h3>Firewall Log</h3>
                <span className="lease-meta">
                  {fwStreaming ? (
                    <><span className="fw-live-dot" /> Live — {fwLogsFiltered.length} entries</>
                  ) : (
                    `${fwLogsFiltered.length} entries · stopped`
                  )}
                </span>
              </div>
              <div className="fw-table-wrap">
                <table className="fw-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Action</th>
                      <th>Dir</th>
                      <th>Iface</th>
                      <th>Proto</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Rule</th>
                      <th>#</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fwLogsFiltered.slice().reverse().map((entry, idx) => (
                      <tr key={idx} className={fwRowClass(entry.action)}>
                        <td className="fw-cell-time">{fwFormatTime(entry.__timestamp__)}</td>
                        <td>
                          <span className={`fw-badge ${fwBadgeClass(entry.action)}`}>
                            {entry.action ?? "?"}
                          </span>
                        </td>
                        <td className="fw-cell-dir">
                          {entry.dir === "in" ? "↓ in" : entry.dir === "out" ? "↑ out" : (entry.dir ?? "?")}
                        </td>
                        <td className="fw-cell-iface">{entry.interface ?? "-"}</td>
                        <td className="fw-cell-proto">{entry.protoname ?? "-"}</td>
                        <td className="fw-cell-addr">
                          {entry.src ?? "-"}
                          {entry.srcport ? <span className="fw-port">:{entry.srcport}</span> : null}
                        </td>
                        <td className="fw-cell-addr">
                          {entry.dst ?? "-"}
                          {entry.dstport ? <span className="fw-port">:{entry.dstport}</span> : null}
                        </td>
                        <td className="fw-cell-label">{entry.label ?? "-"}</td>
                        <td className="fw-cell-count">{entry.counter ?? "-"}</td>
                      </tr>
                    ))}
                    {fwLogsFiltered.length === 0 && (
                      <tr>
                        <td colSpan={9} className="fw-empty">
                          {fwStreaming
                            ? "Waiting for log entries..."
                            : "Press Start in the sidebar to begin streaming firewall log entries."}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === "webfilter" && (
            <div className="card full">
              <div className="preview-header">
                <h3>
                  {wfView === "logs"
                    ? "Schulfilter Plus — Filter Log"
                    : `Schulfilter Plus — ${wfAddressListType === "wl" ? "Whitelist" : "Blacklist"}`}
                </h3>
                <span className="lease-meta">
                  {wfView === "logs"
                    ? (
                      wfLogsBusy
                        ? "Loading…"
                        : wfLogs.length > 0
                        ? `${wfLogsFiltered.length} of ${wfLogs.length} entries`
                        : "No data"
                    )
                    : (
                      wfAddressBusy
                        ? "Loading…"
                        : `${wfAddressEntriesFiltered.length} filtered of ${wfAddressEntries.length} loaded (${wfAddressTotal} reported)`
                    )}
                </span>
              </div>
              {wfView === "logs" ? (
                <div className="fw-table-wrap">
                  <table className="fw-table">
                    <thead>
                      <tr>
                        <th>Action</th>
                        <th>User</th>
                        <th>IP</th>
                        <th>Time</th>
                        <th>URL</th>
                        <th>Category</th>
                      </tr>
                    </thead>
                    <tbody>
                      {wfLogsFiltered.map((entry, idx) => {
                        const isBlock = entry.action.toLowerCase() === "block";
                        const isAllow = entry.action.toLowerCase() === "allow";
                        const normalizedUser = normalizeWebfilterUser(entry.user);
                        const rowClass = isBlock ? "fw-row-block" : "";
                        const badgeClass = isBlock ? "fw-badge-block" : isAllow ? "fw-badge-pass" : "fw-badge-other";
                        return (
                          <tr key={idx} className={rowClass}>
                            <td>
                              <span className={`fw-badge ${badgeClass}`}>{entry.action}</span>
                            </td>
                            <td>{normalizedUser || "-"}</td>
                            <td className="fw-cell-iface">{entry.ip || "-"}</td>
                            <td className="fw-cell-time">{entry.time || "-"}</td>
                            <td className="wf-cell-url" title={entry.url}>{entry.url || "-"}</td>
                            <td className="fw-cell-label">{entry.category || "-"}</td>
                          </tr>
                        );
                      })}
                      {wfLogsFiltered.length === 0 && (
                        <tr>
                          <td colSpan={6} className="fw-empty">
                            {wfLogsBusy
                              ? "Fetching log entries…"
                              : !settings.msdUsername.trim() || !hasMsdPassword
                              ? "Configure MSD credentials in Settings, then press Fetch Logs."
                              : "Press Fetch Logs in the sidebar to load filter log entries."}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              ) : (
                <>
                  <div className="wf-address-toolbar">
                    <input
                      type="text"
                      value={wfAddressSearch}
                      onChange={(e) => setWfAddressSearch(e.target.value)}
                      placeholder="Filter entries..."
                      disabled={wfAddressBusy || wfAddressActionBusy}
                    />
                    <label className="field-hint" style={{ display: "flex", alignItems: "center", gap: "6px", margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wfAddressEntriesFiltered.length > 0 && wfAddressEntriesFiltered.every((entry) => wfAddressSelectedIds.has(entry.id))}
                        onChange={(e) => toggleWfAddressSelectAllVisible(e.target.checked)}
                        disabled={wfAddressEntriesFiltered.length === 0}
                      />
                      Select visible
                    </label>
                  </div>
                  <div className="fw-table-wrap">
                    <table className="fw-table">
                      <thead>
                        <tr>
                          <th style={{ width: "42px" }} />
                          <th>ID</th>
                          <th>Name</th>
                          <th style={{ width: "120px" }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {wfAddressEntriesFiltered.map((entry) => (
                          <tr key={`${wfAddressListType}-${entry.id}`}>
                            <td>
                              <input
                                type="checkbox"
                                checked={wfAddressSelectedIds.has(entry.id)}
                                onChange={(e) => toggleWfAddressSelection(entry.id, e.target.checked)}
                              />
                            </td>
                            <td className="fw-cell-time">{entry.id}</td>
                            <td className="wf-cell-url" title={entry.name}>{entry.name || "-"}</td>
                            <td>
                              <button
                                className="secondary"
                                type="button"
                                disabled={wfAddressActionBusy}
                                onClick={() => {
                                  setWfAddressEditId(entry.id);
                                  setWfAddressEditOriginalName(entry.name);
                                  setWfAddressEditValue(entry.name);
                                }}
                              >
                                Edit
                              </button>
                            </td>
                          </tr>
                        ))}
                        {wfAddressEntriesFiltered.length === 0 && (
                          <tr>
                            <td colSpan={4} className="fw-empty">
                              {wfAddressBusy
                                ? "Loading address list entries…"
                                : "No entries match the current filter."}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          {activeTab === "analysis" && (
            <div className="card full">
              <div className="preview-header">
                <h3>Correlated Security Intelligence</h3>
                <span className="lease-meta">
                  {analysis.rows.length} active IPs · {analysis.correlatedBlocks} overlap blocks
                </span>
              </div>

              <div className="source-health-grid">
                {sourceHealthViews.map((item) => (
                  <div key={`main-${item.key}`} className={`source-health-card source-health-${item.status}`}>
                    <strong>{item.label}</strong>
                    <span>Status: {item.status}</span>
                    <span>Last success: {item.lastSuccessLabel}</span>
                    <span>{item.detail}</span>
                  </div>
                ))}
              </div>

              <div className="analysis-metrics">
                <div className="analysis-metric-card">
                  <span>Known Devices</span>
                  <strong>{analysis.knownDeviceCount}</strong>
                </div>
                <div className="analysis-metric-card">
                  <span>Active Correlated IPs</span>
                  <strong>{analysis.rows.length}</strong>
                </div>
                <div className="analysis-metric-card">
                  <span>High Risk Devices</span>
                  <strong>{analysis.highRiskCount}</strong>
                </div>
                <div className="analysis-metric-card">
                  <span>Dual-Layer Blocks</span>
                  <strong>{analysis.correlatedBlocks}</strong>
                </div>
                <div className="analysis-metric-card">
                  <span>Firewall-Only Blocked Devices</span>
                  <strong>{analysis.fwOnlyBlocked}</strong>
                </div>
                <div className="analysis-metric-card">
                  <span>Webfilter-Only Blocked Devices</span>
                  <strong>{analysis.wfOnlyBlocked}</strong>
                </div>
                <div className="analysis-metric-card">
                  <span>Unknown Private Firewall IPs</span>
                  <strong>{analysis.unknownActiveIps.length}</strong>
                </div>
              </div>

              <div className="analysis-section analysis-section-card">
                <h4>Top Findings</h4>
                <ul className="analysis-findings">
                  {analysis.findings.map((finding, idx) => (
                    <li key={`finding-${idx}`} className={`analysis-finding-${finding.severity}`}>
                      <div className="analysis-finding-head">
                        <span className="analysis-finding-severity">{finding.severity.toUpperCase()}</span>
                        <strong>{finding.title}</strong>
                      </div>
                      <p>{finding.detail}</p>
                    </li>
                  ))}
                  {analysis.findings.length === 0 && <li>No significant findings yet.</li>}
                </ul>
              </div>

              <div className="analysis-section analysis-section-card">
                <h4>Segment Health</h4>
                <div className="fw-table-wrap">
                  <table className="fw-table">
                    <thead>
                      <tr>
                        <th>Segment</th>
                        <th>Known</th>
                        <th>Active</th>
                        <th>FW Block</th>
                        <th>WF Block</th>
                        <th>Dual Block</th>
                        <th>Avg Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analysis.segmentSummary.map((row) => (
                        <tr key={`seg-${row.segment}`}>
                          <td>{row.segment}</td>
                          <td>{row.knownDevices}</td>
                          <td>{row.activeDevices}</td>
                          <td>{row.fwBlock}</td>
                          <td>{row.wfBlock}</td>
                          <td>{row.dualBlockDevices}</td>
                          <td>{row.avgRisk}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="analysis-grid">
                <div className="analysis-section analysis-section-card">
                  <h4>Category Drill-down</h4>
                  <input
                    className="analysis-topic-search"
                    type="text"
                    value={topicSearchPattern}
                    onChange={(e) => setTopicSearchPattern(e.currentTarget.value)}
                    placeholder="Search categories and host context..."
                  />
                  <ul className="analysis-list">
                    {filteredCategoryNodes.map((item) => (
                      <li key={item.id} className="analysis-topic-item">
                        <div>
                          <strong>{item.name}</strong>
                          <p>{item.description}</p>
                        </div>
                        <strong>{item.count}</strong>
                      </li>
                    ))}
                    {filteredCategoryNodes.length === 0 && <li>No matching category data.</li>}
                  </ul>
                </div>
                <div className="analysis-section analysis-section-card">
                  <h4>Top Blocked Destinations</h4>
                  <ul className="analysis-list">
                    {analysis.topBlockedHosts.map((item) => (
                      <li key={`host-${item.label}`}>
                        <span>{item.label}</span>
                        <strong>{item.count}</strong>
                      </li>
                    ))}
                    {analysis.topBlockedHosts.length === 0 && <li>No blocked destination data yet.</li>}
                  </ul>
                </div>
              </div>

              <div className="analysis-section analysis-section-card">
                <div className="analysis-selection-head">
                  <h4>Top Risky Devices</h4>
                  <label className="analysis-selection-toggle">
                    <input
                      type="checkbox"
                      checked={allRiskDevicesSelected}
                      onChange={toggleAllRiskDevices}
                    />
                    Select all
                  </label>
                </div>
                <div className="analysis-bulk-toolbar">
                  <span>{selectedRiskDeviceIps.size} devices selected</span>
                </div>
                <div className="fw-table-wrap">
                  <table className="fw-table">
                    <thead>
                      <tr>
                        <th>Select</th>
                        <th>Risk</th>
                        <th>IP</th>
                        <th>Hostname</th>
                        <th>Segment</th>
                        <th>User</th>
                        <th>FW Block</th>
                        <th>WF Block</th>
                        <th>Dual</th>
                        <th>Identity</th>
                        <th>Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedRiskyDevices.map((row) => (
                        <tr key={`risk-${row.ip}`} className={row.riskScore >= 50 ? "fw-row-block" : ""}>
                          <td>
                            <input
                              type="checkbox"
                              checked={selectedRiskDeviceIps.has(row.ip)}
                              onChange={() => toggleRiskDevice(row.ip)}
                            />
                          </td>
                          <td>{row.riskScore}</td>
                          <td className="fw-cell-addr">
                            <button className="analysis-link-button" type="button" onClick={() => setSelectedAnalysisDeviceIp(row.ip)}>
                              {row.ip}
                            </button>
                          </td>
                          <td>{row.hostname || "-"}</td>
                          <td>{row.segment}</td>
                          <td>{row.user || "-"}</td>
                          <td>{row.fwBlock}</td>
                          <td>{row.wfBlock}</td>
                          <td>{row.hasDualBlock ? "Yes" : "No"}</td>
                          <td>{row.identityConfidence}</td>
                          <td className="fw-cell-time">{row.lastSeen || "-"}</td>
                        </tr>
                      ))}
                      {analysis.riskyDevices.length === 0 && (
                        <tr>
                          <td colSpan={11} className="fw-empty">No risky device data available yet.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <details className="analysis-section analysis-section-card analysis-collapsible">
                <summary>All Correlated Devices</summary>
                <div className="fw-table-wrap">
                  <table className="fw-table">
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>Hostname</th>
                        <th>MAC</th>
                        <th>User</th>
                        <th>Segment</th>
                        <th>Risk</th>
                        <th>FW Pass</th>
                        <th>FW Block</th>
                        <th>WF Allow</th>
                        <th>WF Block</th>
                        <th>Identity</th>
                        <th>Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedAllDevices.map((row) => (
                        <tr key={`analysis-${row.ip}`} className={row.fwBlock > 0 || row.wfBlock > 0 ? "fw-row-block" : ""}>
                          <td className="fw-cell-addr">
                            <button className="analysis-link-button" type="button" onClick={() => setSelectedAnalysisDeviceIp(row.ip)}>
                              {row.ip}
                            </button>
                          </td>
                          <td>{row.hostname || "-"}</td>
                          <td className="fw-cell-addr">{row.mac || "-"}</td>
                          <td>{row.user || "-"}</td>
                          <td>{row.segment}</td>
                          <td>{row.riskScore}</td>
                          <td>{row.fwPass}</td>
                          <td>{row.fwBlock}</td>
                          <td>{row.wfAllow}</td>
                          <td>{row.wfBlock}</td>
                          <td>{row.identityConfidence}</td>
                          <td className="fw-cell-time">{row.lastSeen || "-"}</td>
                        </tr>
                      ))}
                      {analysis.rows.length === 0 && (
                        <tr>
                          <td colSpan={12} className="fw-empty">
                            No correlated activity yet. Start firewall stream and load webfilter logs.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </details>

              <div className="analysis-section analysis-section-card">
                <h4>Unknown Private IPs Seen in Firewall</h4>
                <div className="fw-table-wrap">
                  <table className="fw-table">
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>FW Pass</th>
                        <th>FW Block</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedUnknownIps.map((row) => (
                        <tr key={`unknown-${row.ip}`} className={row.block > 0 ? "fw-row-block" : ""}>
                          <td className="fw-cell-addr">{row.ip}</td>
                          <td>{row.pass}</td>
                          <td>{row.block}</td>
                        </tr>
                      ))}
                      {analysis.unknownActiveIps.length === 0 && (
                        <tr>
                          <td colSpan={3} className="fw-empty">No unknown private IP activity detected.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {showLeaseViews && leaseView === "dynamic" && (
            <div className="card full">
              <div className="preview-header">
                <h3>Dynamic Leases</h3>
                <button className="mini-action" type="button" onClick={() => void handleLoadDynamicLeases()} disabled={dynamicBusy}>
                  {dynamicBusy ? "Refreshing..." : "Refresh"}
                </button>
              </div>
              {dynamicError && <p className="error-text">{dynamicError}</p>}
              {dynamicMeta && (
                <p className="lease-meta">
                  Movable (Gruen/WLANBYOD): {dynamicMeta.movableCount} · Info only (other): {dynamicMeta.infoCount}
                </p>
              )}
              <div className="dynamic-table-wrap">
                <table className="dynamic-table">
                  <thead>
                    <tr>
                      <th>Move</th>
                      <th>Interface</th>
                      <th>Hostname</th>
                      <th>MAC</th>
                      <th>IP</th>
                      <th>Status</th>
                      <th>Online</th>
                      <th>Start</th>
                      <th>End</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dynamicLeases.map((lease) => {
                      const badges = getDynamicRowBadges(lease, existing.rows);
                      return (
                      <tr key={`${lease.iface}|${lease.mac}|${lease.ip}`}>
                        <td>
                          {lease.movableToStatic ? (
                            <button
                              className="mini-action"
                              type="button"
                              onClick={() => openMoveDynamicPrompt(lease)}
                              disabled={moveDynamicBusy}
                            >
                              Move
                            </button>
                          ) : (
                            "No"
                          )}
                        </td>
                        <td>{lease.iface}</td>
                        <td>
                          <div>{lease.hostname || "-"}</div>
                          {badges.length > 0 && (
                            <div className="dynamic-badges">
                              {badges.map((badge) => (
                                <span key={`${lease.iface}|${lease.mac}|${lease.ip}|${badge}`} className="dynamic-badge">
                                  {badge}
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td>{lease.mac}</td>
                        <td>{lease.ip}</td>
                        <td>{lease.status || "-"}</td>
                        <td>{lease.online ? "Yes" : "No"}</td>
                        <td>{lease.start || "-"}</td>
                        <td>{lease.end || "-"}</td>
                      </tr>
                      );
                    })}
                    {dynamicLeases.length === 0 && !dynamicBusy && (
                      <tr>
                        <td colSpan={9} className="dynamic-empty">
                          No dynamic leases loaded yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {showLeaseViews && leaseView === "review" && (
            <div className="card full">
              <h3>Review</h3>
              <p className="lease-meta">Final check before export or apply.</p>
              <div className="diff-grid">
                <div>
                  <span>Add</span>
                  <strong>{diff.adds.length}</strong>
                </div>
                <div>
                  <span>Conflicts</span>
                  <strong>{diff.conflicts.length}</strong>
                </div>
                <div>
                  <span>Deletes</span>
                  <strong>{displayDeletes.length}</strong>
                </div>
                <div>
                  <span>Ignored</span>
                  <strong>{incoming.ignored.length + existing.ignored.length}</strong>
                </div>
              </div>
              <div className="review-readiness">
                <p>
                  Credentials: <strong>{credentialsReady ? "Ready" : "Missing"}</strong>
                </p>
                <p>
                  Confirmation: <strong>{confirmChanges ? "Checked" : "Not checked"}</strong>
                </p>
                <p>
                  Validation: <strong>{incoming.errors.length === 0 && existing.errors.length === 0 ? "OK" : "Needs attention"}</strong>
                </p>
              </div>
              <label className="confirm-toggle">
                <input
                  type="checkbox"
                  checked={confirmChanges}
                  onChange={(e) => setConfirmChanges(e.currentTarget.checked)}
                />
                I understand the changes above
              </label>
              {hasIgnored && (
                <label className="confirm-toggle">
                  <input
                    type="checkbox"
                    checked={acknowledgeIgnored}
                    onChange={(e) => setAcknowledgeIgnored(e.currentTarget.checked)}
                  />
                  Acknowledge ignored rows to continue
                </label>
              )}
              {runBlockers.length > 0 && (
                <div className="run-hints">
                  {runBlockers.map((item) => (
                    <p key={`review-${item}`}>{item}</p>
                  ))}
                </div>
              )}
              <div className="review-actions">
                <button className="secondary" type="button" onClick={() => setLeaseView("static")}>
                  Open Static Gruen
                </button>
                <button className="secondary" type="button" onClick={() => setLeaseView("dynamic")}>
                  Open Dynamic
                </button>
                <button className="secondary" type="button" disabled={!canExport || isRunning} onClick={handleExport}>
                  Export Current List
                </button>
                <button className="primary" type="button" disabled={!canRun || isRunning} onClick={() => void handleRun()}>
                  {isRunning ? "Running..." : "Run Changes"}
                </button>
              </div>
            </div>
          )}

          {showLeaseViews && leaseView === "runlog" && (
            <div className="card full logs">
              <h3>Run Log</h3>
              {runError && <p className="error-text">{runError}</p>}
              <pre>{logs.join("\n") || "No runs yet."}</pre>
            </div>
          )}

          {showLeaseViews && leaseView === "static" && (
            <>
          <div className="card full">
            <div className="preview-header">
              <h3>Static Leases</h3>
              <button
                className="mini-action"
                type="button"
                onClick={() => void refreshStaticLeases()}
                disabled={staticRefreshBusy}
              >
                {staticRefreshBusy ? "Refreshing..." : "Refresh static list"}
              </button>
            </div>
          </div>
          <div className="grid">
            <div className="card">
              <h3>Validation</h3>
              <div className="metrics">
                <span>Incoming</span>
                <strong>{incoming.rows.length}</strong>
                <span>Existing</span>
                <strong>{existing.rows.length}</strong>
              </div>
            </div>
            <div className="card">
              <h3>Diff Summary</h3>
              <div className="diff-grid">
                <div>
                  <span>Add</span>
                  <strong>{diff.adds.length}</strong>
                </div>
                <div>
                  <span>Conflicts</span>
                  <strong>{diff.conflicts.length}</strong>
                </div>
                <div>
                  <span>Exact</span>
                  <strong>{diff.exact.length}</strong>
                </div>
                <div>
                  <span>Duplicates</span>
                  <strong>{diff.duplicates.length}</strong>
                </div>
              </div>
            </div>
          </div>

          {(incoming.ignored.length > 0 || existing.ignored.length > 0) && (
            <div className="card full ignored-card">
              <div className="ignored-header">
                <h3>Ignored</h3>
                <p>Rows skipped during validation with the reason listed.</p>
              </div>
              <div
                className={`ignored-columns ${
                  incoming.ignored.length > 0 && existing.ignored.length > 0 ? "" : "single"
                }`}
              >
                {incoming.ignored.length > 0 && (
                  <div className="ignored-section">
                    <h4>Incoming</h4>
                    <ul className="ignored-list">
                      {incoming.ignored.map((item, idx) => (
                        <li key={`ignored-in-${item.lineNumber}-${idx}`} className="ignored-item">
                          <div className="ignored-main">
                            <span className="ignored-entry">
                              {item.name || item.mac || item.ip
                                ? `${item.name || "?"} · ${item.mac || "?"} · ${item.ip || "?"}`
                                : item.raw || "(empty row)"}
                            </span>
                            <span className="ignored-reason">{item.reason}</span>
                          </div>
                          <span className="ignored-meta">Row {item.lineNumber}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {existing.ignored.length > 0 && (
                  <div className="ignored-section">
                    <h4>Existing</h4>
                    <ul className="ignored-list">
                      {existing.ignored.map((item, idx) => (
                        <li key={`ignored-ex-${item.lineNumber}-${idx}`} className="ignored-item">
                          <div className="ignored-main">
                            <span className="ignored-entry">
                              {item.name || item.mac || item.ip
                                ? `${item.name || "?"} · ${item.mac || "?"} · ${item.ip || "?"}`
                                : item.raw || "(empty row)"}
                            </span>
                            <span className="ignored-reason">{item.reason}</span>
                          </div>
                          <span className="ignored-meta">Row {item.lineNumber}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="card full">
            <h3>Change Preview</h3>
            <div className="preview-columns">
              <div className="preview-stack">
                <div className="preview-section">
                  <div className="preview-header">
                    <h4>Add</h4>
                    <div className="preview-actions">
                      <button
                        className="mini-action"
                        type="button"
                        onClick={() => setAddCollapsed((prev) => !prev)}
                      >
                        {addCollapsed ? `Show (${diff.adds.length})` : `Hide (${diff.adds.length})`}
                      </button>
                      {!addCollapsed && (
                        <button
                          className="mini-action"
                          type="button"
                          onClick={toggleAllAdds}
                          disabled={diff.adds.length === 0}
                        >
                          {allAddsChecked ? "Uncheck all" : "Check all"}
                        </button>
                      )}
                    </div>
                  </div>
                  {!addCollapsed && (
                    <ul>
                      {diff.adds.map((row) => (
                        <li key={`add-${row.mac}`}>
                          <label className="select-row">
                            <input
                              type="checkbox"
                              checked={!excludedAddKeys.has(rowKey(row))}
                              onChange={() => {
                                const key = rowKey(row);
                                setExcludedAddKeys((prev) => {
                                  const next = new Set(prev);
                                  if (next.has(key)) next.delete(key);
                                  else next.add(key);
                                  return next;
                                });
                              }}
                            />
                            <span>{row.name} · {row.mac} · {row.ip}</span>
                          </label>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="preview-section conflicts">
                  <div className="preview-header">
                    <h4>Conflicts</h4>
                    <div className="preview-actions">
                      <button
                        className="mini-action"
                        type="button"
                        onClick={() => setEditCollapsed((prev) => !prev)}
                      >
                        {editCollapsed ? `Show (${diff.conflicts.length})` : `Hide (${diff.conflicts.length})`}
                      </button>
                      {!editCollapsed && (
                        <button
                          className="mini-action"
                          type="button"
                          onClick={toggleAllConflicts}
                          disabled={diff.conflicts.length === 0}
                        >
                          {allConflictsChecked ? "Uncheck all" : "Check all"}
                        </button>
                      )}
                    </div>
                  </div>
                  {!editCollapsed && (
                    <ul className="conflict-list">
                      {diff.conflicts.map(({ incoming, existing }) => (
                        <li key={`conf-${incoming.mac}-${existing.mac}`}>
                          <label className="select-row">
                            <input
                              type="checkbox"
                              checked={!excludedConflictKeys.has(rowKey(incoming))}
                              onChange={() => {
                                handleConflictToggle(incoming, existing);
                              }}
                            />
                            <span>Apply change</span>
                          </label>
                          <div className="conflict-row">
                            <div className="conflict-side">
                              <span className="conflict-label">Existing</span>
                              <div className="conflict-values">
                                <span className={incoming.name !== existing.name ? "conflict-change" : ""}>
                                  {existing.name}
                                </span>
                                <span className={incoming.mac !== existing.mac ? "conflict-change" : ""}>
                                  {existing.mac}
                                </span>
                                <span className={incoming.ip !== existing.ip ? "conflict-change" : ""}>
                                  {existing.ip}
                                </span>
                              </div>
                            </div>
                            <div className="conflict-arrow">→</div>
                            <div className="conflict-side">
                              <span className="conflict-label">Incoming</span>
                              <div className="conflict-values">
                                <span className={incoming.name !== existing.name ? "conflict-change" : ""}>
                                  {incoming.name}
                                </span>
                                <span className={incoming.mac !== existing.mac ? "conflict-change" : ""}>
                                  {incoming.mac}
                                </span>
                                <span className={incoming.ip !== existing.ip ? "conflict-change" : ""}>
                                  {incoming.ip}
                                </span>
                              </div>
                            </div>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="preview-section deletions">
                  <div className="preview-header">
                    <h4>Deletes</h4>
                    <div className="preview-actions">
                      <button
                        className="mini-action"
                        type="button"
                        onClick={() => setDeleteCollapsed((prev) => !prev)}
                      >
                        {deleteCollapsed ? `Show (${displayDeletes.length})` : `Hide (${displayDeletes.length})`}
                      </button>
                      {!deleteCollapsed && (
                        <button
                          className="mini-action"
                          type="button"
                          onClick={toggleAllDeletes}
                          disabled={diff.deletes.length === 0}
                        >
                          {allDeletesChecked ? "Uncheck all" : "Check all"}
                        </button>
                      )}
                    </div>
                  </div>
                  {!deleteCollapsed && (
                    <ul>
                      {displayDeletes.map((row) => {
                        const forced = forcedDeleteKeys.has(rowKey(row));
                        return (
                        <li key={`del-${row.mac}`}>
                          <label className="select-row">
                            <input
                              type="checkbox"
                              checked={selectedDeleteKeys.has(rowKey(row))}
                              disabled={forced}
                              onChange={() => {
                                const key = rowKey(row);
                                setSelectedDeleteKeys((prev) => {
                                  const next = new Set(prev);
                                  if (next.has(key)) next.delete(key);
                                  else next.add(key);
                                  return next;
                                });
                              }}
                            />
                            <span>{row.name} · {row.mac} · {row.ip}</span>
                            {forced && <span className="pill">Required</span>}
                          </label>
                        </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
                <div className="preview-section">
                  <div className="preview-header">
                    <h4>Exact Matches</h4>
                    <button
                      className="mini-action"
                      type="button"
                      onClick={() => setExactCollapsed((prev) => !prev)}
                    >
                      {exactCollapsed ? `Show (${diff.exact.length})` : `Hide (${diff.exact.length})`}
                    </button>
                  </div>
                  {!exactCollapsed && (
                    <ul>
                      {diff.exact.map((row) => (
                        <li key={`exact-${row.mac}`}>{row.name} · {row.mac} · {row.ip}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="card full confirm">
            <div>
              <h3>Ready to apply</h3>
              <p>Review the changes, then confirm to execute the run.</p>
            </div>
            <label className="confirm-toggle">
              <input
                type="checkbox"
                checked={confirmChanges}
                onChange={(e) => setConfirmChanges(e.currentTarget.checked)}
              />
              I understand the changes above
            </label>
            {hasIgnored && (
              <label className="confirm-toggle">
                <input
                  type="checkbox"
                  checked={acknowledgeIgnored}
                  onChange={(e) => setAcknowledgeIgnored(e.currentTarget.checked)}
                />
                I understand some rows will be ignored
              </label>
            )}
            {runBlockers.length > 0 && (
              <div className="run-hints">
                {runBlockers.map((item) => (
                  <p key={item}>{item}</p>
                ))}
              </div>
            )}
            <div className="run-toggles">
              <label className="toggle-pill">
                <input
                  id="dryrun-toggle"
                  type="checkbox"
                  checked={settings.dryRun}
                  onChange={(e) => {
                    const checked = e.currentTarget.checked;
                    setSettings((prev) => ({ ...prev, dryRun: checked }));
                  }}
                />
                Dry run
              </label>
            </div>
            <button className="primary" disabled={!canRun || isRunning} onClick={handleRun}>
              {isRunning ? "Running..." : "Run Changes"}
            </button>
            <button className="secondary" type="button" disabled={!canExport || isRunning} onClick={handleExport}>
              Export Current List
            </button>
          </div>

          </>
          )}

          {showLeaseViews && leaseView === "staticWlanbyod" && (
            <>
          <div className="card full">
            <div className="preview-header">
              <h3>Static Leases (WLANBYOD / opt4)</h3>
              <button
                className="mini-action"
                type="button"
                onClick={() => void refreshStaticLeases()}
                disabled={staticRefreshBusy}
              >
                {staticRefreshBusy ? "Refreshing..." : "Refresh static list"}
              </button>
            </div>
          </div>
          <div className="grid">
            <div className="card">
              <h3>Validation</h3>
              <div className="metrics">
                <span>Incoming</span>
                <strong>{incomingW.rows.length}</strong>
                <span>Existing</span>
                <strong>{existingW.rows.length}</strong>
              </div>
            </div>
            <div className="card">
              <h3>Diff Summary</h3>
              <div className="diff-grid">
                <div><span>Add</span><strong>{diffW.adds.length}</strong></div>
                <div><span>Conflicts</span><strong>{diffW.conflicts.length}</strong></div>
                <div><span>Exact</span><strong>{diffW.exact.length}</strong></div>
                <div><span>Duplicates</span><strong>{diffW.duplicates.length}</strong></div>
              </div>
            </div>
          </div>

          {(incomingW.ignored.length > 0 || existingW.ignored.length > 0) && (
            <div className="card full ignored-card">
              <div className="ignored-header">
                <h3>Ignored</h3>
                <p>Rows skipped during validation with the reason listed.</p>
              </div>
              <div className={`ignored-columns ${incomingW.ignored.length > 0 && existingW.ignored.length > 0 ? "" : "single"}`}>
                {incomingW.ignored.length > 0 && (
                  <div className="ignored-section">
                    <h4>Incoming</h4>
                    <ul className="ignored-list">
                      {incomingW.ignored.map((item, idx) => (
                        <li key={`ign-win-${item.lineNumber}-${idx}`} className="ignored-item">
                          <div className="ignored-main">
                            <span className="ignored-entry">
                              {item.name || item.mac || item.ip ? `${item.name || "?"} · ${item.mac || "?"} · ${item.ip || "?"}` : item.raw || "(empty row)"}
                            </span>
                            <span className="ignored-reason">{item.reason}</span>
                          </div>
                          <span className="ignored-meta">Row {item.lineNumber}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {existingW.ignored.length > 0 && (
                  <div className="ignored-section">
                    <h4>Existing</h4>
                    <ul className="ignored-list">
                      {existingW.ignored.map((item, idx) => (
                        <li key={`ign-wex-${item.lineNumber}-${idx}`} className="ignored-item">
                          <div className="ignored-main">
                            <span className="ignored-entry">
                              {item.name || item.mac || item.ip ? `${item.name || "?"} · ${item.mac || "?"} · ${item.ip || "?"}` : item.raw || "(empty row)"}
                            </span>
                            <span className="ignored-reason">{item.reason}</span>
                          </div>
                          <span className="ignored-meta">Row {item.lineNumber}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="card full">
            <h3>Change Preview</h3>
            <div className="preview-columns">
              <div className="preview-stack">
                <div className="preview-section">
                  <div className="preview-header">
                    <h4>Add</h4>
                    <div className="preview-actions">
                      <button className="mini-action" type="button" onClick={() => setAddCollapsedW((p) => !p)}>
                        {addCollapsedW ? `Show (${diffW.adds.length})` : `Hide (${diffW.adds.length})`}
                      </button>
                      {!addCollapsedW && (
                        <button className="mini-action" type="button" onClick={toggleAllAddsW} disabled={diffW.adds.length === 0}>
                          {allAddsCheckedW ? "Uncheck all" : "Check all"}
                        </button>
                      )}
                    </div>
                  </div>
                  {!addCollapsedW && (
                    <ul>
                      {diffW.adds.map((row) => (
                        <li key={`wadd-${row.mac}`}>
                          <label className="select-row">
                            <input
                              type="checkbox"
                              checked={!excludedAddKeysW.has(rowKey(row))}
                              onChange={() => {
                                const key = rowKey(row);
                                setExcludedAddKeysW((prev) => { const next = new Set(prev); if (next.has(key)) next.delete(key); else next.add(key); return next; });
                              }}
                            />
                            <span>{row.name} · {row.mac} · {row.ip}</span>
                          </label>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="preview-section conflicts">
                  <div className="preview-header">
                    <h4>Conflicts</h4>
                    <div className="preview-actions">
                      <button className="mini-action" type="button" onClick={() => setEditCollapsedW((p) => !p)}>
                        {editCollapsedW ? `Show (${diffW.conflicts.length})` : `Hide (${diffW.conflicts.length})`}
                      </button>
                      {!editCollapsedW && (
                        <button className="mini-action" type="button" onClick={toggleAllConflictsW} disabled={diffW.conflicts.length === 0}>
                          {allConflictsCheckedW ? "Uncheck all" : "Check all"}
                        </button>
                      )}
                    </div>
                  </div>
                  {!editCollapsedW && (
                    <ul className="conflict-list">
                      {diffW.conflicts.map(({ incoming: inc, existing: ex }) => (
                        <li key={`wconf-${inc.mac}-${ex.mac}`}>
                          <label className="select-row">
                            <input
                              type="checkbox"
                              checked={!excludedConflictKeysW.has(rowKey(inc))}
                              onChange={() => handleConflictToggleW(inc, ex)}
                            />
                            <span>Apply change</span>
                          </label>
                          <div className="conflict-row">
                            <div className="conflict-side">
                              <span className="conflict-label">Existing</span>
                              <div className="conflict-values">
                                <span className={inc.name !== ex.name ? "conflict-change" : ""}>{ex.name}</span>
                                <span className={inc.mac !== ex.mac ? "conflict-change" : ""}>{ex.mac}</span>
                                <span className={inc.ip !== ex.ip ? "conflict-change" : ""}>{ex.ip}</span>
                              </div>
                            </div>
                            <div className="conflict-arrow">→</div>
                            <div className="conflict-side">
                              <span className="conflict-label">Incoming</span>
                              <div className="conflict-values">
                                <span className={inc.name !== ex.name ? "conflict-change" : ""}>{inc.name}</span>
                                <span className={inc.mac !== ex.mac ? "conflict-change" : ""}>{inc.mac}</span>
                                <span className={inc.ip !== ex.ip ? "conflict-change" : ""}>{inc.ip}</span>
                              </div>
                            </div>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="preview-section deletions">
                  <div className="preview-header">
                    <h4>Deletes</h4>
                    <div className="preview-actions">
                      <button className="mini-action" type="button" onClick={() => setDeleteCollapsedW((p) => !p)}>
                        {deleteCollapsedW ? `Show (${displayDeletesW.length})` : `Hide (${displayDeletesW.length})`}
                      </button>
                      {!deleteCollapsedW && (
                        <button className="mini-action" type="button" onClick={toggleAllDeletesW} disabled={diffW.deletes.length === 0}>
                          {allDeletesCheckedW ? "Uncheck all" : "Check all"}
                        </button>
                      )}
                    </div>
                  </div>
                  {!deleteCollapsedW && (
                    <ul>
                      {displayDeletesW.map((row) => {
                        const forced = forcedDeleteKeysW.has(rowKey(row));
                        return (
                          <li key={`wdel-${row.mac}`}>
                            <label className="select-row">
                              <input
                                type="checkbox"
                                checked={selectedDeleteKeysW.has(rowKey(row))}
                                disabled={forced}
                                onChange={() => {
                                  const key = rowKey(row);
                                  setSelectedDeleteKeysW((prev) => { const next = new Set(prev); if (next.has(key)) next.delete(key); else next.add(key); return next; });
                                }}
                              />
                              <span>{row.name} · {row.mac} · {row.ip}</span>
                              {forced && <span className="pill">Required</span>}
                            </label>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
                <div className="preview-section">
                  <div className="preview-header">
                    <h4>Exact Matches</h4>
                    <button className="mini-action" type="button" onClick={() => setExactCollapsedW((p) => !p)}>
                      {exactCollapsedW ? `Show (${diffW.exact.length})` : `Hide (${diffW.exact.length})`}
                    </button>
                  </div>
                  {!exactCollapsedW && (
                    <ul>
                      {diffW.exact.map((row) => (
                        <li key={`wexact-${row.mac}`}>{row.name} · {row.mac} · {row.ip}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="card full confirm">
            <div>
              <h3>Ready to apply (WLANBYOD)</h3>
              <p>Review the changes, then confirm to execute the run on opt4.</p>
            </div>
            <label className="confirm-toggle">
              <input
                type="checkbox"
                checked={confirmChangesW}
                onChange={(e) => setConfirmChangesW(e.currentTarget.checked)}
              />
              I understand the changes above
            </label>
            {hasIgnoredW && (
              <label className="confirm-toggle">
                <input
                  type="checkbox"
                  checked={acknowledgeIgnoredW}
                  onChange={(e) => setAcknowledgeIgnoredW(e.currentTarget.checked)}
                />
                I understand some rows will be ignored
              </label>
            )}
            {runBlockersW.length > 0 && (
              <div className="run-hints">
                {runBlockersW.map((item) => (
                  <p key={`w-${item}`}>{item}</p>
                ))}
              </div>
            )}
            <div className="run-toggles">
              <label className="toggle-pill">
                <input
                  type="checkbox"
                  checked={settings.dryRun}
                  onChange={(e) => { const checked = e.currentTarget.checked; setSettings((prev) => ({ ...prev, dryRun: checked })); }}
                />
                Dry run
              </label>
            </div>
            <button className="primary" disabled={!canRunW || isRunning} onClick={() => void handleRunW()}>
              {isRunning ? "Running..." : "Run Changes (WLANBYOD)"}
            </button>
            <button className="secondary" type="button" disabled={!canExport || isRunning} onClick={() => void handleExportW()}>
              Export Current List
            </button>
          </div>

            </>
          )}
        </section>
        </div>
      </div>
    </div>
  );
}

export default App;
