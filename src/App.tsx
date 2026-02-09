import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
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
  pythonPath: string;
  headless: boolean;
  dryRun: boolean;
  selectors: {
    addButton: string;
    editButton: string;
    cancelEditButton: string;
  };
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
  pythonPath: "python",
  headless: true,
  dryRun: false,
  selectors: {
    addButton: "button.btnAddLease[data-iface='lan']",
    editButton: "button.btnEditLease",
    cancelEditButton: "button.btnCancelEditLease",
  },
};

function normalizeSettings(loaded?: Partial<SettingsState> | null): SettingsState {
  if (!loaded) return DEFAULT_SETTINGS;
  return {
    ...DEFAULT_SETTINGS,
    ...loaded,
    selectors: {
      ...DEFAULT_SETTINGS.selectors,
      ...(loaded.selectors ?? {}),
    },
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

function App() {
  const [activeTab, setActiveTab] = useState<"console" | "settings" | "history" | "help">("console");
  const [settings, setSettings] = useState<SettingsState>(DEFAULT_SETTINGS);
  const [history, setHistory] = useState<RunRecord[]>([]);
  const [incomingCsv, setIncomingCsv] = useState("");
  const [existingCsv, setExistingCsv] = useState("");
  const [updateMode, setUpdateMode] = useState<"skip" | "update">("skip");
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
  }, [incomingCsv, existingCsv]);

  useEffect(() => {
    if (updateMode === "skip") {
      setExcludedConflictKeys(new Set(diff.conflicts.map(({ incoming }) => rowKey(incoming))));
      return;
    }
    setExcludedConflictKeys(new Set());
  }, [diff.conflicts, updateMode]);

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
    diff.deletes.length > 0 && diff.deletes.every((row) => selectedDeleteKeys.has(rowKey(row)));

  const runBlockers = [
    incoming.rows.length === 0 ? "Incoming CSV is empty" : null,
    incoming.errors.length > 0 ? "Incoming CSV has validation errors" : null,
    existing.errors.length > 0 ? "Existing CSV has validation errors" : null,
    hasIgnored && !acknowledgeIgnored ? "Acknowledge ignored rows to continue" : null,
    settings.username.trim().length === 0 ? "Enter a username in Settings" : null,
    !hasPassword ? "Save a password in Settings" : null,
    !confirmChanges ? "Confirm the changes to enable running" : null,
  ].filter(Boolean) as string[];

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
      const result = await invoke<RunRecord>("export_static", { payload: { settings } });
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

  async function handleSaveSettings() {
    try {
      await invoke("save_settings", { settings });
      if (passwordInput.trim().length > 0) {
        await invoke("save_password", { password: passwordInput });
        setPasswordInput("");
        setHasPassword(true);
        setLogs(["Settings and password saved."]);
      } else {
        setLogs(["Settings saved."]);
      }

      if (settings.username.trim().length > 0 && hasPassword && hasRealUrls) {
        setAutoExportPrompt(true);
      }
    } catch (error) {
      setRunError(String(error));
    } finally {
      setAutoExporting(false);
    }
  }

  function handleFile(event: React.ChangeEvent<HTMLInputElement>, target: "incoming" | "existing") {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result ?? "");
      if (target === "incoming") setIncomingCsv(text);
      else setExistingCsv(text);
    };
    reader.readAsText(file);
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
      const deleteRows = diff.deletes.filter((row) => selectedDeleteKeys.has(rowKey(row)));
      const deleteCsv = buildDeleteCsv(deleteRows);
      if (existingCsv.trim().length === 0) {
        const exportResult = await invoke<RunRecord>("export_static", { payload: { settings } });
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
        updateMode,
        settings,
      };
      const result = await invoke<RunRecord>("run_dhcp", { payload });
      setHistory((prev) => [result, ...prev]);
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
      const savePath = await save({
        filters: [{ name: "CSV", extensions: ["csv"] }],
        defaultPath: "export_static.csv",
      });
      if (!savePath) {
        setLogs(["Export canceled."]);
        return;
      }
      const result = await invoke<RunRecord>("export_static", {
        payload: { settings, savePath },
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

  async function handleInstallBrowsers() {
    setHelpBusy(true);
    try {
      const result = await invoke<HelpResult>("install_playwright_browsers", {
        pythonPath: settings.pythonPath,
      });
      setHelpLogs(result.lines);
    } catch (error) {
      setHelpLogs([`Install Playwright browsers failed: ${error}`]);
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
    if (diff.deletes.length === 0) return;
    if (allDeletesChecked) {
      setSelectedDeleteKeys(new Set());
      return;
    }
    setSelectedDeleteKeys(new Set(diff.deletes.map(rowKey)));
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
          <span>Update Mode</span>
          <strong>{updateMode === "update" ? "Update Conflicts" : "Skip Conflicts"}</strong>
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
                <label>Update behavior on conflict</label>
                <div className="segmented">
                  <button
                    type="button"
                    className={updateMode === "skip" ? "active" : ""}
                    onClick={() => setUpdateMode("skip")}
                  >
                    Skip
                  </button>
                  <button
                    type="button"
                    className={updateMode === "update" ? "active" : ""}
                    onClick={() => setUpdateMode("update")}
                  >
                    Update
                  </button>
                </div>
              </div>
              <div className="field">
                <label>Import incoming CSV</label>
                <input type="file" accept=".csv" onChange={(e) => handleFile(e, "incoming")} />
              </div>
              <div className="field">
                <label>Import existing export CSV</label>
                <input type="file" accept=".csv" onChange={(e) => handleFile(e, "existing")} />
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
                <label htmlFor="add-selector">Add button selector</label>
                <input
                  id="add-selector"
                  type="text"
                  value={settings.selectors.addButton}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({
                      ...prev,
                      selectors: { ...prev.selectors, addButton: value },
                    }));
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="edit-selector">Edit button selector</label>
                <input
                  id="edit-selector"
                  type="text"
                  value={settings.selectors.editButton}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({
                      ...prev,
                      selectors: { ...prev.selectors, editButton: value },
                    }));
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="cancel-selector">Cancel edit selector</label>
                <input
                  id="cancel-selector"
                  type="text"
                  value={settings.selectors.cancelEditButton}
                  onChange={(e) => {
                    const value = e.currentTarget.value;
                    setSettings((prev) => ({
                      ...prev,
                      selectors: { ...prev.selectors, cancelEditButton: value },
                    }));
                  }}
                />
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
                This app uses the bundled automation script. Use the buttons below to prepare Python and
                Playwright if needed.
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
                <h3>3) Install Playwright browsers</h3>
                <p>Download the required browser binaries for automation.</p>
                <button className="secondary" type="button" onClick={handleInstallBrowsers} disabled={helpBusy}>
                  {helpBusy ? "Working..." : "Install Playwright browsers"}
                </button>
              </div>
              <div className="help-section">
                <h3>Checklist</h3>
                <ul className="help-list">
                  <li>Enter OPNsense URLs and username in Settings.</li>
                  <li>Save a password in Settings (stored securely).</li>
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
                      disabled={diff.conflicts.length === 0 || updateMode === "skip"}
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
                              const key = rowKey(incoming);
                              setExcludedConflictKeys((prev) => {
                                const next = new Set(prev);
                                if (next.has(key)) next.delete(key);
                                else next.add(key);
                                return next;
                              });
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
                    {diff.deletes.map((row) => (
                      <li key={`del-${row.mac}`}>
                        <label className="select-row">
                          <input
                            type="checkbox"
                            checked={selectedDeleteKeys.has(rowKey(row))}
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
                        </label>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="preview-section">
                  <h4>Exact Matches</h4>
                  <ul>
                    {diff.exact.map((row) => (
                      <li key={`exact-${row.mac}`}>{row.name} · {row.mac} · {row.ip}</li>
                    ))}
                  </ul>
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
                  id="headless-toggle"
                  type="checkbox"
                  checked={settings.headless}
                  onChange={(e) => {
                    const checked = e.currentTarget.checked;
                    setSettings((prev) => ({ ...prev, headless: checked }));
                  }}
                />
                Headless
              </label>
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
