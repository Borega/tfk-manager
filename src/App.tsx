import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { getVersion } from "@tauri-apps/api/app";
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

type RunPayload = {
  incomingCsv: string;
  existingCsv: string;
  deleteCsv: string;
  updateMode: "skip" | "update";
  settings: SettingsState;
};

type RunRecord = {
  timestamp: string;
  lines: string[];
  exportCsv?: string;
};

type UpdateInfo = Awaited<ReturnType<typeof check>>;

const DEFAULT_SETTINGS: SettingsState = {
  baseUrl: "https://your-opnsense-host",
  loginUrl: "https://your-opnsense-host",
  dashboardUrl: "https://your-opnsense-host/ui/core/dashboard",
  username: "",
  apiUsername: "",
  apiKey: "",
  apiSecret: "",
  cookieHeader: "",
  pythonPath: "python",
  dryRun: false,
  debug: false,
};

function normalizeSettings(loaded?: Partial<SettingsState> | null): SettingsState {
  if (!loaded) return DEFAULT_SETTINGS;
  return {
    ...DEFAULT_SETTINGS,
    ...loaded,
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

function App() {
  const UPDATE_MODE: RunPayload["updateMode"] = "update";
  const [activeTab, setActiveTab] = useState<"console" | "settings" | "history" | "help">("console");
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
  const [helpLogs, setHelpLogs] = useState<string[]>([]);
  const [helpBusy, setHelpBusy] = useState(false);
  const [excludedAddKeys, setExcludedAddKeys] = useState<Set<string>>(new Set());
  const [excludedConflictKeys, setExcludedConflictKeys] = useState<Set<string>>(new Set());
  const [selectedDeleteKeys, setSelectedDeleteKeys] = useState<Set<string>>(new Set());
    const [forcedDeleteRows, setForcedDeleteRows] = useState<Record<string, ClientRow>>({});
    const [deletePrompt, setDeletePrompt] = useState<ConflictDeletePrompt | null>(null);
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
  const [exactCollapsed, setExactCollapsed] = useState(true);
  const [appVersion, setAppVersion] = useState<string | null>(null);

  const incoming = useMemo(() => parseCsv(incomingCsv), [incomingCsv]);
  const existing = useMemo(() => parseCsv(existingCsv), [existingCsv]);

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

  useEffect(() => {
    setExcludedAddKeys(new Set());
    setExcludedConflictKeys(new Set());
    setSelectedDeleteKeys(new Set());
    setAcknowledgeIgnored(false);
    setExactCollapsed(true);
  }, [incomingCsv, existingCsv]);

  const credentialsReady = settings.username.trim().length > 0 && hasPassword;
  const hasRealUrls =
    settings.baseUrl.trim() !== DEFAULT_SETTINGS.baseUrl &&
    settings.loginUrl.trim() !== DEFAULT_SETTINGS.loginUrl &&
    settings.dashboardUrl.trim() !== DEFAULT_SETTINGS.dashboardUrl &&
    settings.baseUrl.trim().length > 0 &&
    settings.loginUrl.trim().length > 0 &&
    settings.dashboardUrl.trim().length > 0;
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
        setLogs(["Settings and password saved."]);
      } else {
        setLogs(["Settings saved."]);
      }

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

  function handleConflictToggle(incoming: ClientRow, existingRow: ClientRow) {
    const key = rowKey(incoming);
    const currentlyChecked = !excludedConflictKeys.has(key);
    if (currentlyChecked) {
      setExcludedConflictKeys((prev) => {
        const next = new Set(prev);
        next.add(key);
        return next;
      });
      return;
    }

    const secondary = findSecondaryConflict(incoming, existingRow);
    if (secondary) {
      setDeletePrompt({ incoming, existing: existingRow, conflict: secondary });
      return;
    }

    setExcludedConflictKeys((prev) => {
      const next = new Set(prev);
      next.delete(key);
      return next;
    });
  }

  function confirmDeleteConflict() {
    if (!deletePrompt) return;
    const { incoming, conflict } = deletePrompt;
    const incomingKey = rowKey(incoming);
    const conflictKey = rowKey(conflict.row);
    setExcludedConflictKeys((prev) => {
      const next = new Set(prev);
      next.delete(incomingKey);
      return next;
    });
    setForcedDeleteRows((prev) => ({ ...prev, [conflictKey]: conflict.row }));
    setSelectedDeleteKeys((prev) => {
      const next = new Set(prev);
      next.add(conflictKey);
      return next;
    });
    setDeletePrompt(null);
  }

  function cancelDeleteConflict() {
    setDeletePrompt(null);
  }

  return (
    <div
      className={`app ${
        autoExporting || autoExportPrompt || isRunning || showUpdateOverlay ? "app-busy" : ""
      }`}
    >
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
      <div className="app-content">
        <header className="topbar">
        <div>
          <p className="eyebrow">TFK Manager</p>
          <h1>Static DHCP Control Room</h1>
          <p className="subhead">Validate, diff, and apply CSV changes with a modern, audit-first workflow.</p>
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
              className={activeTab === "console" ? "active" : ""}
              onClick={() => setActiveTab("console")}
            >
              Console
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
          </div>

          {activeTab === "console" && (
            <div className="tab-panel">
              <h2>Run Console</h2>
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
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, loginUrl: value }));
                  }}
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
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({ ...prev, dashboardUrl: value }));
                  }}
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
        </aside>

        <section className="panel main">
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
                    <button
                      className="mini-action"
                      type="button"
                      onClick={toggleAllAdds}
                      disabled={diff.adds.length === 0}
                    >
                      {allAddsChecked ? "Uncheck all" : "Check all"}
                    </button>
                  </div>
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
                </div>
                <div className="preview-section conflicts">
                  <div className="preview-header">
                    <h4>Conflicts</h4>
                    <button
                      className="mini-action"
                      type="button"
                      onClick={toggleAllConflicts}
                      disabled={diff.conflicts.length === 0}
                    >
                      {allConflictsChecked ? "Uncheck all" : "Check all"}
                    </button>
                  </div>
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
                </div>
                <div className="preview-section deletions">
                  <div className="preview-header">
                    <h4>Deletes</h4>
                    <button
                      className="mini-action"
                      type="button"
                      onClick={toggleAllDeletes}
                      disabled={diff.deletes.length === 0}
                    >
                      {allDeletesChecked ? "Uncheck all" : "Check all"}
                    </button>
                  </div>
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

          <div className="card full logs">
            <h3>Run Log</h3>
            {runError && <p className="error-text">{runError}</p>}
            <pre>{logs.join("\n") || "No runs yet."}</pre>
          </div>
        </section>
        </div>
      </div>
    </div>
  );
}

export default App;
