import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
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
};

type RunPayload = {
  incomingCsv: string;
  existingCsv: string;
  updateMode: "skip" | "update";
  settings: SettingsState;
};

type RunRecord = {
  timestamp: string;
  lines: string[];
  exportCsv?: string;
};

const DEFAULT_SETTINGS: SettingsState = {
  baseUrl: "https://your-opnsense-host",
  loginUrl: "https://your-opnsense-host",
  dashboardUrl: "https://your-opnsense-host/ui/core/dashboard",
  username: "",
  pythonPath: "python",
  headless: true,
  dryRun: true,
  selectors: {
    addButton: "#staticdhcpleases_opt3 > div > div > div:nth-child(1) > button",
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

const MAC_RE = /^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$/;
const IP_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function parseCsv(text: string): ParseResult {
  const errors: string[] = [];
  const rows: ClientRow[] = [];
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length === 0) {
    return { rows, errors };
  }

  const header = lines[0].split(";").map((h) => h.trim().toLowerCase());
  const indexMap = new Map<string, number>();
  header.forEach((h, i) => indexMap.set(h, i));

  const nameIndex = indexMap.get("name") ?? indexMap.get("geraet");
  const macIndex = indexMap.get("mac");
  const ipIndex = indexMap.get("ip");

  if (nameIndex === undefined || macIndex === undefined || ipIndex === undefined) {
    errors.push("Missing required columns: Name/Geraet, MAC, IP");
    return { rows, errors };
  }

  lines.slice(1).forEach((line, idx) => {
    const parts = line.split(";");
    const name = (parts[nameIndex] ?? "").trim();
    const mac = (parts[macIndex] ?? "").trim();
    const ip = (parts[ipIndex] ?? "").trim();

    if (!name || !mac || !ip) {
      errors.push(`Row ${idx + 2}: missing fields`);
      return;
    }
    if (!MAC_RE.test(mac)) {
      errors.push(`Row ${idx + 2}: invalid MAC ${mac}`);
      return;
    }
    if (!IP_RE.test(ip)) {
      errors.push(`Row ${idx + 2}: invalid IP ${ip}`);
      return;
    }
    rows.push({ name, mac, ip });
  });

  return { rows, errors };
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

  const incoming = useMemo(() => parseCsv(incomingCsv), [incomingCsv]);
  const existing = useMemo(() => parseCsv(existingCsv), [existingCsv]);

  const diff = useMemo(() => {
    const exact: ClientRow[] = [];
    const conflicts: { incoming: ClientRow; existing: ClientRow }[] = [];
    const adds: ClientRow[] = [];
    const duplicates: ClientRow[] = [];

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

    return { exact, conflicts, adds, duplicates };
  }, [incoming.rows, existing.rows]);

  useEffect(() => {
    setExcludedAddKeys(new Set());
    setExcludedConflictKeys(new Set());
  }, [incomingCsv, existingCsv]);

  const credentialsReady = settings.username.trim().length > 0 && hasPassword;
  const canExport = credentialsReady;

  const canRun =
    incoming.rows.length > 0 &&
    incoming.errors.length === 0 &&
    existing.errors.length === 0 &&
    confirmChanges &&
    credentialsReady;

  const runBlockers = [
    incoming.rows.length === 0 ? "Incoming CSV is empty" : null,
    incoming.errors.length > 0 ? "Incoming CSV has validation errors" : null,
    existing.errors.length > 0 ? "Existing CSV has validation errors" : null,
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
    if (!settingsLoaded) return;
    invoke("save_settings", { settings }).catch(() => undefined);
  }, [settings, settingsLoaded]);

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
    } catch (error) {
      setRunError(String(error));
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
    }
  }

  async function handleExport() {
    if (!credentialsReady) {
      setRunError("Username and saved password are required.");
      setLogs(["Missing credentials. Open Settings to save them."]);
      return;
    }
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

  return (
    <div className="app">
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
              {(incoming.errors.length > 0 || existing.errors.length > 0) && (
                <div className="errors">
                  {incoming.errors.map((err) => (
                    <p key={`inc-${err}`}>{err}</p>
                  ))}
                  {existing.errors.map((err) => (
                    <p key={`ext-${err}`}>{err}</p>
                  ))}
                </div>
              )}
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

          <div className="card full">
            <h3>Change Preview</h3>
            <div className="preview-columns">
              <div className="preview-stack">
                <div className="preview-section">
                  <h4>Add</h4>
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
                  <h4>Conflicts</h4>
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
  );
}

export default App;
