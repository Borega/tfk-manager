use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread;
use tauri::{Emitter, Manager};
use keyring::Entry;

#[derive(Default)]
struct ProcessState {
    child: Mutex<Option<std::process::Child>>,
}

#[derive(Default)]
struct FirewallLogState {
    child: Mutex<Option<std::process::Child>>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UiSettings {
    base_url: String,
    login_url: String,
    dashboard_url: String,
    username: String,
    #[serde(default)]
    api_username: String,
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    api_secret: String,
    #[serde(default)]
    cookie_header: String,
    python_path: String,
    dry_run: bool,
    #[serde(default)]
    debug: bool,
    #[serde(default)]
    msd_username: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RunPayload {
    incoming_csv: String,
    existing_csv: String,
    delete_csv: String,
    update_mode: String,
    settings: UiSettings,
    #[serde(default)]
    iface: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RunRecord {
    timestamp: String,
    lines: Vec<String>,
    #[serde(alias = "export_csv")]
    export_csv: Option<String>,
    #[serde(alias = "export_wlanbyod_csv", skip_serializing_if = "Option::is_none", default)]
    export_wlanbyod_csv: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ExportPayload {
    settings: UiSettings,
    save_path: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
struct HelpResult {
    ok: bool,
    lines: Vec<String>,
    value: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ApiBootstrapResult {
    ok: bool,
    lines: Vec<String>,
    settings: UiSettings,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DynamicLease {
    iface: String,
    ip: String,
    mac: String,
    hostname: String,
    start: String,
    end: String,
    status: String,
    online: bool,
    movable_to_static: bool,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DynamicLeasesResult {
    ok: bool,
    rows: Vec<DynamicLease>,
    movable_count: usize,
    info_count: usize,
    lease_source: String,
    lease_source_detail: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct MoveDynamicLeasePayload {
    settings: UiSettings,
    iface: String,
    ip: String,
    mac: String,
    hostname: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct MoveDynamicLeaseResult {
    ok: bool,
    status: String,
    message: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateStaticFromDynamicPayload {
    settings: UiSettings,
    old_mac: String,
    iface: String,
    ip: String,
    mac: String,
    hostname: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateStaticFromDynamicResult {
    ok: bool,
    status: String,
    message: String,
}

fn app_data_dir_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|err| err.to_string())?;
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    Ok(dir)
}

fn app_data_file(app: &tauri::AppHandle, name: &str) -> Result<PathBuf, String> {
    let dir = app_data_dir_path(app)?;
    Ok(dir.join(name))
}

fn ensure_backend_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app_data_dir_path(app)?.join("backend-data");
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    Ok(dir)
}

fn read_export_csv(data_dir: &Path) -> Option<String> {
    let path = data_dir.join("export_static.csv");
    fs::read_to_string(&path).ok()
}

fn read_export_wlanbyod_csv(data_dir: &Path) -> Option<String> {
    let path = data_dir.join("export_static_wlanbyod.csv");
    fs::read_to_string(&path).ok()
}

fn resolve_script_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("backend").join("src").join("opnsense_dhcp_ui.py"));
        candidates.push(current.join("backend").join("opnsense_dhcp_ui.py"));
        candidates.push(current.join("src").join("opnsense_dhcp_ui.py"));
        candidates.push(current.join("..").join("backend").join("src").join("opnsense_dhcp_ui.py"));
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join("backend").join("src").join("opnsense_dhcp_ui.py"));
        candidates.push(resource_dir.join("backend").join("opnsense_dhcp_ui.py"));
        candidates.push(resource_dir.join("opnsense_dhcp_ui.py"));
        candidates.push(
            resource_dir
                .join("resources")
                .join("backend")
                .join("src")
                .join("opnsense_dhcp_ui.py"),
        );
        candidates.push(
            resource_dir
                .join("resources")
                .join("backend")
                .join("opnsense_dhcp_ui.py"),
        );
    }

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    Err("Could not locate backend/src/opnsense_dhcp_ui.py. Place the backend folder next to the app or run from the repo root.".to_string())
}

fn resolve_backend_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let script = resolve_script_path(app)?;
    script
        .parent()
        .and_then(|dir| dir.parent())
        .map(|dir| dir.to_path_buf())
        .ok_or_else(|| "Could not resolve backend directory".to_string())
}

fn capture_output(command: &mut Command) -> HelpResult {
    let mut lines: Vec<String> = Vec::new();
    let output = command.output();
    match output {
        Ok(result) => {
            if !result.stdout.is_empty() {
                lines.push("--- stdout ---".to_string());
                lines.extend(String::from_utf8_lossy(&result.stdout).lines().map(|l| l.to_string()));
            }
            if !result.stderr.is_empty() {
                lines.push("--- stderr ---".to_string());
                lines.extend(String::from_utf8_lossy(&result.stderr).lines().map(|l| l.to_string()));
            }
            HelpResult {
                ok: result.status.success(),
                lines,
                value: None,
            }
        }
        Err(err) => HelpResult {
            ok: false,
            lines: vec![format!("Failed to run: {}", err)],
            value: None,
        },
    }
}

fn try_python_path(path: &Path) -> bool {
    path.exists()
}

#[tauri::command]
fn find_python(app: tauri::AppHandle) -> Result<HelpResult, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join(".venv").join("Scripts").join("python.exe"));
        candidates.push(current.join(".venv").join("bin").join("python"));
        candidates.push(current.join("backend").join(".venv").join("Scripts").join("python.exe"));
        candidates.push(current.join("backend").join(".venv").join("bin").join("python"));
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join(".venv").join("Scripts").join("python.exe"));
        candidates.push(resource_dir.join(".venv").join("bin").join("python"));
        candidates.push(resource_dir.join("backend").join(".venv").join("Scripts").join("python.exe"));
        candidates.push(resource_dir.join("backend").join(".venv").join("bin").join("python"));
    }

    for candidate in candidates {
        if try_python_path(&candidate) {
            return Ok(HelpResult {
                ok: true,
                lines: vec![format!("Found Python at {}", candidate.display())],
                value: Some(candidate.to_string_lossy().to_string()),
            });
        }
    }

    let mut lines: Vec<String> = Vec::new();
    if cfg!(windows) {
        let mut cmd = Command::new("where");
        cmd.arg("python");
        let result = capture_output(&mut cmd);
        let first_line = result.lines.iter().skip_while(|l| l.starts_with("---")).next().cloned();
        lines.extend(result.lines);
        if result.ok {
            if let Some(first) = first_line {
                return Ok(HelpResult {
                    ok: true,
                    lines,
                    value: Some(first.to_string()),
                });
            }
        }
    } else {
        let mut cmd = Command::new("which");
        cmd.arg("python3");
        let result = capture_output(&mut cmd);
        let first_line = result.lines.iter().skip_while(|l| l.starts_with("---")).next().cloned();
        lines.extend(result.lines);
        if result.ok {
            if let Some(first) = first_line {
                return Ok(HelpResult {
                    ok: true,
                    lines,
                    value: Some(first.to_string()),
                });
            }
        }
    }

    Ok(HelpResult {
        ok: false,
        lines: vec!["Python not found. Install Python 3.11+ and try again.".to_string()],
        value: None,
    })
}

#[tauri::command]
fn install_backend_deps(app: tauri::AppHandle, python_path: String) -> Result<HelpResult, String> {
    let backend_dir = resolve_backend_dir(&app)?;
    let requirements = backend_dir.join("requirements.txt");
    let mut cmd = Command::new(python_path);
    cmd.arg("-m")
        .arg("pip")
        .arg("install")
        .arg("-r")
        .arg(requirements);
    Ok(capture_output(&mut cmd))
}

fn credential_entry() -> Result<Entry, String> {
    Entry::new("tfk-manager", "opnsense").map_err(|err| err.to_string())
}

fn emit_line(app: &tauri::AppHandle, line: &str) {
    let _ = app.emit("run-log", line.to_string());
}

fn run_with_live_logs(
    app: &tauri::AppHandle,
    state: &tauri::State<ProcessState>,
    mut command: Command,
    lines: &mut Vec<String>,
) -> Result<std::process::ExitStatus, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|err| err.to_string())?;

    let stdout = child.stdout.take().ok_or_else(|| "Missing stdout".to_string())?;
    let stderr = child.stderr.take().ok_or_else(|| "Missing stderr".to_string())?;

    {
        let mut guard = state.child.lock().map_err(|_| "Process lock poisoned".to_string())?;
        *guard = Some(child);
    }

    let (tx, rx) = mpsc::channel::<(String, String)>();
    let tx_out = tx.clone();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().flatten() {
            let _ = tx_out.send(("stdout".to_string(), line));
        }
    });
    let tx_err = tx.clone();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().flatten() {
            let _ = tx_err.send(("stderr".to_string(), line));
        }
    });
    drop(tx);

    let mut saw_stdout = false;
    let mut saw_stderr = false;
    for (stream, line) in rx {
        if stream == "stdout" && !saw_stdout {
            saw_stdout = true;
            lines.push("--- stdout ---".to_string());
            emit_line(app, "--- stdout ---");
        }
        if stream == "stderr" && !saw_stderr {
            saw_stderr = true;
            lines.push("--- stderr ---".to_string());
            emit_line(app, "--- stderr ---");
        }
        lines.push(line.clone());
        emit_line(app, &line);
    }

    let mut guard = state.child.lock().map_err(|_| "Process lock poisoned".to_string())?;
    if let Some(mut child) = guard.take() {
        child.wait().map_err(|err| err.to_string())
    } else {
        Err("Process handle missing".to_string())
    }
}

fn get_password() -> Result<Option<String>, String> {
    let entry = credential_entry()?;
    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err.to_string()),
    }
}

#[tauri::command]
fn save_password(password: String) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("Password is empty".to_string());
    }
    let entry = credential_entry()?;
    entry.set_password(&password).map_err(|err| err.to_string())
}

#[tauri::command]
fn has_password() -> Result<bool, String> {
    Ok(get_password()?.is_some())
}

fn msd_credential_entry() -> Result<Entry, String> {
    Entry::new("tfk-manager", "msd").map_err(|err| err.to_string())
}

fn get_msd_password() -> Result<Option<String>, String> {
    let entry = msd_credential_entry()?;
    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err.to_string()),
    }
}

#[tauri::command]
fn save_msd_password(password: String) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("MSD password is empty".to_string());
    }
    let entry = msd_credential_entry()?;
    entry.set_password(&password).map_err(|err| err.to_string())
}

#[tauri::command]
fn has_msd_password() -> Result<bool, String> {
    Ok(get_msd_password()?.is_some())
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterPayload {
    settings: UiSettings,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diag: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterLogEntry {
    action: String,
    user: String,
    ip: String,
    time: String,
    url: String,
    category: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterLogsResult {
    ok: bool,
    #[serde(default)]
    entries: Vec<WebfilterLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diag: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterAddressListEntry {
    id: String,
    name: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterAddressListsResult {
    ok: bool,
    #[serde(default)]
    whitelist_entries: Vec<WebfilterAddressListEntry>,
    #[serde(default)]
    blacklist_entries: Vec<WebfilterAddressListEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    whitelist_total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blacklist_total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diag: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterAddressListWritePayload {
    settings: UiSettings,
    action: String,
    list_type: String,
    #[serde(default)]
    entry_id: Option<String>,
    #[serde(default)]
    entry_name: Option<String>,
    #[serde(default)]
    current_name: Option<String>,
    #[serde(default)]
    entry_ids: Vec<String>,
    #[serde(default)]
    import_text: Option<String>,
    #[serde(default)]
    save_path: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebfilterAddressListWriteResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    export_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    export_filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    imported_lines: Option<usize>,
    #[serde(default)]
    warnings: Vec<String>,
}

#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    fs::read_to_string(path).map_err(|err| err.to_string())
}

#[tauri::command]
fn load_settings(app: tauri::AppHandle) -> Result<Option<UiSettings>, String> {
    let path = app_data_file(&app, "settings.json")?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let parsed = serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    Ok(Some(parsed))
}

#[tauri::command]
fn save_settings(app: tauri::AppHandle, settings: UiSettings) -> Result<(), String> {
    let path = app_data_file(&app, "settings.json")?;
    let raw = serde_json::to_string_pretty(&settings).map_err(|err| err.to_string())?;
    fs::write(path, raw).map_err(|err| err.to_string())?;
    Ok(())
}

#[tauri::command]
fn load_history(app: tauri::AppHandle) -> Result<Vec<RunRecord>, String> {
    let path = app_data_file(&app, "history.json")?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let parsed = serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    Ok(parsed)
}

fn run_dhcp_sync(app: &tauri::AppHandle, payload: RunPayload) -> Result<RunRecord, String> {
    let incoming_lines = payload.incoming_csv.lines().count().saturating_sub(1);
    let existing_lines = payload.existing_csv.lines().count().saturating_sub(1);
    let script_path = resolve_script_path(app)?;

    let password = get_password().unwrap_or(None);

    let config_path = app_data_file(app, "last_run_settings.json")?;
    let config_raw = serde_json::to_string_pretty(&payload.settings).map_err(|err| err.to_string())?;
    fs::write(&config_path, config_raw).map_err(|err| err.to_string())?;

    let incoming_path = app_data_file(app, "incoming.csv")?;
    fs::write(&incoming_path, &payload.incoming_csv).map_err(|err| err.to_string())?;

    let delete_path = app_data_file(app, "delete.csv")?;
    fs::write(&delete_path, &payload.delete_csv).map_err(|err| err.to_string())?;

    let mut lines = vec![
        format!("Run started"),
        format!("Incoming rows: {}", incoming_lines),
        format!("Existing rows: {}", existing_lines),
        format!("Update mode: {}", payload.update_mode),
        format!("Dry run: {}", payload.settings.dry_run),
        format!("Debug: {}", payload.settings.debug),
    ];
    for line in &lines {
        emit_line(app, line);
    }

    if password.is_none() {
        lines.push("No stored password found; login prompt may appear.".to_string());
    }

    let data_dir = ensure_backend_data_dir(app)?;
    let mut command = Command::new(&payload.settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_SETTINGS_JSON", &config_path)
        .env("TFK_INCOMING_CSV", &incoming_path)
        .env("TFK_DELETE_CSV", &delete_path)
        .env("TFK_UPDATE_MODE", &payload.update_mode)
        .env("TFK_DATA_DIR", &data_dir)
        .env("TFK_AUTO_CONFIRM", "1")
        .env("PYTHONUNBUFFERED", "1");
    if payload.settings.debug {
        command.env("TFK_DEBUG", "1");
    }
    if !payload.settings.username.trim().is_empty() {
        command.env("TFK_USERNAME", &payload.settings.username);
    }
    if !payload.settings.api_username.trim().is_empty() {
        command.env("TFK_API_USERNAME", &payload.settings.api_username);
    }
    if !payload.settings.api_key.trim().is_empty() {
        command.env("TFK_API_KEY", &payload.settings.api_key);
    }
    if !payload.settings.api_secret.trim().is_empty() {
        command.env("TFK_API_SECRET", &payload.settings.api_secret);
    }
    if !payload.settings.cookie_header.trim().is_empty() {
        command.env("TFK_COOKIE_HEADER", &payload.settings.cookie_header);
    }
    if let Some(password) = password {
        command.env("TFK_PASSWORD", password);
    }
    if let Some(iface) = &payload.iface {
        let trimmed = iface.trim();
        if !trimmed.is_empty() {
            command.env("TFK_IFACE", trimmed);
        }
    }

    let state = app.state::<ProcessState>();
    let status = run_with_live_logs(app, &state, command, &mut lines)?;
    if !status.success() {
        let message = format!("Process exited with code {}", status);
        lines.push(message.clone());
        emit_line(app, &message);
    }

    let record = RunRecord {
        timestamp: chrono::Local::now().to_rfc3339(),
        lines,
        export_csv: None,
        export_wlanbyod_csv: None,
    };
    let mut history = load_history(app.clone()).unwrap_or_default();
    history.insert(0, record.clone());
    let history_path = app_data_file(app, "history.json")?;
    let history_raw = serde_json::to_string_pretty(&history).map_err(|err| err.to_string())?;
    fs::write(history_path, history_raw).map_err(|err| err.to_string())?;

    Ok(record)
}

#[tauri::command]
async fn run_dhcp(app: tauri::AppHandle, payload: RunPayload) -> Result<RunRecord, String> {
    let app_handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || run_dhcp_sync(&app_handle, payload))
        .await
        .map_err(|err| err.to_string())?
}

fn export_static_sync(app: &tauri::AppHandle, payload: ExportPayload) -> Result<RunRecord, String> {
    let settings = payload.settings;
    let config_path = app_data_file(app, "last_run_settings.json")?;
    let config_raw = serde_json::to_string_pretty(&settings).map_err(|err| err.to_string())?;
    fs::write(&config_path, config_raw).map_err(|err| err.to_string())?;
    let script_path = resolve_script_path(app)?;
    let data_dir = ensure_backend_data_dir(app)?;
    let password = get_password().unwrap_or(None);

    let mut lines = vec![
        "Export started".to_string(),
        format!("Dry run: {}", settings.dry_run),
        format!("Debug: {}", settings.debug),
    ];
    for line in &lines {
        emit_line(app, line);
    }

    if password.is_none() {
        lines.push("No stored password found; login prompt may appear.".to_string());
    }

    let mut command = Command::new(&settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_SETTINGS_JSON", &config_path)
        .env("TFK_MODE", "export")
        .env("TFK_DATA_DIR", &data_dir)
        .env("PYTHONUNBUFFERED", "1");
    if settings.debug {
        command.env("TFK_DEBUG", "1");
    }
    if !settings.username.trim().is_empty() {
        command.env("TFK_USERNAME", &settings.username);
    }
    if !settings.api_username.trim().is_empty() {
        command.env("TFK_API_USERNAME", &settings.api_username);
    }
    if !settings.api_key.trim().is_empty() {
        command.env("TFK_API_KEY", &settings.api_key);
    }
    if !settings.api_secret.trim().is_empty() {
        command.env("TFK_API_SECRET", &settings.api_secret);
    }
    if !settings.cookie_header.trim().is_empty() {
        command.env("TFK_COOKIE_HEADER", &settings.cookie_header);
    }
    if let Some(password) = password {
        command.env("TFK_PASSWORD", password);
    }

    let state = app.state::<ProcessState>();
    let status = run_with_live_logs(app, &state, command, &mut lines)?;
    if !status.success() {
        let message = format!("Process exited with code {}", status);
        lines.push(message.clone());
        emit_line(app, &message);
    }

    let export_csv = read_export_csv(&data_dir);
    let export_wlanbyod_csv = read_export_wlanbyod_csv(&data_dir);
    if let (Some(path), Some(csv)) = (payload.save_path.as_ref(), export_csv.as_ref()) {
        match fs::write(path, csv) {
            Ok(()) => lines.push(format!("Saved export to {}", path)),
            Err(err) => lines.push(format!("Failed to save export: {}", err)),
        }
    }

    let record = RunRecord {
        timestamp: chrono::Local::now().to_rfc3339(),
        lines,
        export_csv,
        export_wlanbyod_csv,
    };
    let mut history = load_history(app.clone()).unwrap_or_default();
    history.insert(0, record.clone());
    let history_path = app_data_file(app, "history.json")?;
    let history_raw = serde_json::to_string_pretty(&history).map_err(|err| err.to_string())?;
    fs::write(history_path, history_raw).map_err(|err| err.to_string())?;

    Ok(record)
}

#[tauri::command]
async fn export_static(app: tauri::AppHandle, payload: ExportPayload) -> Result<RunRecord, String> {
    let app_handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || export_static_sync(&app_handle, payload))
        .await
        .map_err(|err| err.to_string())?
}

fn discover_api_credentials_sync(
    app: &tauri::AppHandle,
    payload: ExportPayload,
) -> Result<ApiBootstrapResult, String> {
    let mut settings = payload.settings;
    let config_path = app_data_file(app, "last_run_settings.json")?;
    let config_raw = serde_json::to_string_pretty(&settings).map_err(|err| err.to_string())?;
    fs::write(&config_path, config_raw).map_err(|err| err.to_string())?;
    let script_path = resolve_script_path(app)?;
    let data_dir = ensure_backend_data_dir(app)?;
    let password = get_password().unwrap_or(None);

    let mut lines = vec!["API bootstrap started".to_string()];
    emit_line(app, "API bootstrap started");

    let mut command = Command::new(&settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_SETTINGS_JSON", &config_path)
        .env("TFK_MODE", "bootstrap_api")
        .env("TFK_DATA_DIR", &data_dir)
        .env("PYTHONUNBUFFERED", "1");
    if settings.debug {
        command.env("TFK_DEBUG", "1");
    }
    if !settings.username.trim().is_empty() {
        command.env("TFK_USERNAME", &settings.username);
    }
    if !settings.api_username.trim().is_empty() {
        command.env("TFK_API_USERNAME", &settings.api_username);
    }
    if !settings.api_key.trim().is_empty() {
        command.env("TFK_API_KEY", &settings.api_key);
    }
    if !settings.api_secret.trim().is_empty() {
        command.env("TFK_API_SECRET", &settings.api_secret);
    }
    if !settings.cookie_header.trim().is_empty() {
        command.env("TFK_COOKIE_HEADER", &settings.cookie_header);
    }
    if let Some(password) = password {
        command.env("TFK_PASSWORD", password);
    }

    let state = app.state::<ProcessState>();
    let status = run_with_live_logs(app, &state, command, &mut lines)?;
    if !status.success() {
        let message = format!("Process exited with code {}", status);
        lines.push(message.clone());
        emit_line(app, &message);
    }

    let raw = fs::read_to_string(&config_path).map_err(|err| err.to_string())?;
    settings = serde_json::from_str(&raw).map_err(|err| err.to_string())?;

    let settings_path = app_data_file(app, "settings.json")?;
    let settings_raw = serde_json::to_string_pretty(&settings).map_err(|err| err.to_string())?;
    fs::write(settings_path, settings_raw).map_err(|err| err.to_string())?;

    Ok(ApiBootstrapResult {
        ok: status.success(),
        lines,
        settings,
    })
}

#[tauri::command]
async fn discover_api_credentials(
    app: tauri::AppHandle,
    payload: ExportPayload,
) -> Result<ApiBootstrapResult, String> {
    let app_handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || discover_api_credentials_sync(&app_handle, payload))
        .await
        .map_err(|err| err.to_string())?
}

fn load_dynamic_leases_sync(
    app: &tauri::AppHandle,
    payload: ExportPayload,
) -> Result<DynamicLeasesResult, String> {
    let settings = payload.settings;
    let config_path = app_data_file(app, "last_run_settings.json")?;
    let config_raw = serde_json::to_string_pretty(&settings).map_err(|err| err.to_string())?;
    fs::write(&config_path, config_raw).map_err(|err| err.to_string())?;
    let script_path = resolve_script_path(app)?;
    let data_dir = ensure_backend_data_dir(app)?;
    let password = get_password().unwrap_or(None);

    let mut command = Command::new(&settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_SETTINGS_JSON", &config_path)
        .env("TFK_MODE", "dynamic")
        .env("TFK_DATA_DIR", &data_dir)
        .env("PYTHONUNBUFFERED", "1");
    if settings.debug {
        command.env("TFK_DEBUG", "1");
    }
    if !settings.username.trim().is_empty() {
        command.env("TFK_USERNAME", &settings.username);
    }
    if !settings.api_username.trim().is_empty() {
        command.env("TFK_API_USERNAME", &settings.api_username);
    }
    if !settings.api_key.trim().is_empty() {
        command.env("TFK_API_KEY", &settings.api_key);
    }
    if !settings.api_secret.trim().is_empty() {
        command.env("TFK_API_SECRET", &settings.api_secret);
    }
    if !settings.cookie_header.trim().is_empty() {
        command.env("TFK_COOKIE_HEADER", &settings.cookie_header);
    }
    if let Some(password) = password {
        command.env("TFK_PASSWORD", password);
    }

    let output = command.output().map_err(|err| err.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(format!(
            "Dynamic lease fetch failed ({}). stdout: {} stderr: {}",
            output.status, stdout, stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parsed: Option<DynamicLeasesResult> = None;
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<DynamicLeasesResult>(trimmed) {
            parsed = Some(value);
            break;
        }
    }

    parsed.ok_or_else(|| "Could not parse dynamic lease JSON output".to_string())
}

#[tauri::command]
async fn load_dynamic_leases(
    app: tauri::AppHandle,
    payload: ExportPayload,
) -> Result<DynamicLeasesResult, String> {
    let app_handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || load_dynamic_leases_sync(&app_handle, payload))
        .await
        .map_err(|err| err.to_string())?
}

fn move_dynamic_to_static_sync(
    app: &tauri::AppHandle,
    payload: MoveDynamicLeasePayload,
) -> Result<MoveDynamicLeaseResult, String> {
    let config_path = app_data_file(app, "last_run_settings.json")?;
    let config_raw = serde_json::to_string_pretty(&payload.settings).map_err(|err| err.to_string())?;
    fs::write(&config_path, config_raw).map_err(|err| err.to_string())?;
    let script_path = resolve_script_path(app)?;
    let data_dir = ensure_backend_data_dir(app)?;
    let password = get_password().unwrap_or(None);

    let mut command = Command::new(&payload.settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_SETTINGS_JSON", &config_path)
        .env("TFK_MODE", "move_dynamic")
        .env("TFK_DATA_DIR", &data_dir)
        .env("TFK_DYNAMIC_IFACE", &payload.iface)
        .env("TFK_DYNAMIC_IP", &payload.ip)
        .env("TFK_DYNAMIC_MAC", &payload.mac)
        .env("TFK_DYNAMIC_HOSTNAME", &payload.hostname)
        .env("PYTHONUNBUFFERED", "1");
    if payload.settings.debug {
        command.env("TFK_DEBUG", "1");
    }
    if !payload.settings.username.trim().is_empty() {
        command.env("TFK_USERNAME", &payload.settings.username);
    }
    if !payload.settings.api_username.trim().is_empty() {
        command.env("TFK_API_USERNAME", &payload.settings.api_username);
    }
    if !payload.settings.api_key.trim().is_empty() {
        command.env("TFK_API_KEY", &payload.settings.api_key);
    }
    if !payload.settings.api_secret.trim().is_empty() {
        command.env("TFK_API_SECRET", &payload.settings.api_secret);
    }
    if !payload.settings.cookie_header.trim().is_empty() {
        command.env("TFK_COOKIE_HEADER", &payload.settings.cookie_header);
    }
    if let Some(password) = password {
        command.env("TFK_PASSWORD", password);
    }

    let output = command.output().map_err(|err| err.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parsed: Option<MoveDynamicLeaseResult> = None;
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<MoveDynamicLeaseResult>(trimmed) {
            parsed = Some(value);
            break;
        }
    }

    let result = parsed.ok_or_else(|| "Could not parse move-dynamic JSON output".to_string())?;
    if !output.status.success() && result.ok {
        return Err("Dynamic move exited with error status".to_string());
    }
    Ok(result)
}

#[tauri::command]
async fn move_dynamic_to_static(
    app: tauri::AppHandle,
    payload: MoveDynamicLeasePayload,
) -> Result<MoveDynamicLeaseResult, String> {
    let app_handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || move_dynamic_to_static_sync(&app_handle, payload))
        .await
        .map_err(|err| err.to_string())?
}

fn update_static_from_dynamic_sync(
    app: &tauri::AppHandle,
    payload: UpdateStaticFromDynamicPayload,
) -> Result<UpdateStaticFromDynamicResult, String> {
    let config_path = app_data_file(app, "last_run_settings.json")?;
    let config_raw = serde_json::to_string_pretty(&payload.settings).map_err(|err| err.to_string())?;
    fs::write(&config_path, config_raw).map_err(|err| err.to_string())?;
    let script_path = resolve_script_path(app)?;
    let data_dir = ensure_backend_data_dir(app)?;
    let password = get_password().unwrap_or(None);

    let mut command = Command::new(&payload.settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_SETTINGS_JSON", &config_path)
        .env("TFK_MODE", "update_dynamic_conflict")
        .env("TFK_DATA_DIR", &data_dir)
        .env("TFK_DYNAMIC_OLD_MAC", &payload.old_mac)
        .env("TFK_DYNAMIC_IFACE", &payload.iface)
        .env("TFK_DYNAMIC_IP", &payload.ip)
        .env("TFK_DYNAMIC_MAC", &payload.mac)
        .env("TFK_DYNAMIC_HOSTNAME", &payload.hostname)
        .env("PYTHONUNBUFFERED", "1");
    if payload.settings.debug {
        command.env("TFK_DEBUG", "1");
    }
    if !payload.settings.username.trim().is_empty() {
        command.env("TFK_USERNAME", &payload.settings.username);
    }
    if !payload.settings.api_username.trim().is_empty() {
        command.env("TFK_API_USERNAME", &payload.settings.api_username);
    }
    if !payload.settings.api_key.trim().is_empty() {
        command.env("TFK_API_KEY", &payload.settings.api_key);
    }
    if !payload.settings.api_secret.trim().is_empty() {
        command.env("TFK_API_SECRET", &payload.settings.api_secret);
    }
    if !payload.settings.cookie_header.trim().is_empty() {
        command.env("TFK_COOKIE_HEADER", &payload.settings.cookie_header);
    }
    if let Some(password) = password {
        command.env("TFK_PASSWORD", password);
    }

    let output = command.output().map_err(|err| err.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parsed: Option<UpdateStaticFromDynamicResult> = None;
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<UpdateStaticFromDynamicResult>(trimmed) {
            parsed = Some(value);
            break;
        }
    }

    let result = parsed.ok_or_else(|| "Could not parse update-static JSON output".to_string())?;
    if !output.status.success() && result.ok {
        return Err("Static update exited with error status".to_string());
    }
    Ok(result)
}

#[tauri::command]
async fn update_static_from_dynamic(
    app: tauri::AppHandle,
    payload: UpdateStaticFromDynamicPayload,
) -> Result<UpdateStaticFromDynamicResult, String> {
    let app_handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || update_static_from_dynamic_sync(&app_handle, payload))
        .await
        .map_err(|err| err.to_string())?
}

fn resolve_firewall_stream_script(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    // Firewall streaming is now a mode of the main script — no separate file needed.
    resolve_script_path(app)
}

fn resolve_webfilter_script_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // Prefer locating fetch_webfilter.py next to the resolved main backend script.
    // If opnsense_dhcp_ui.py is found, this keeps all script lookups in the same backend copy.
    if let Ok(main_script) = resolve_script_path(app) {
        if let Some(src_dir) = main_script.parent() {
            candidates.push(src_dir.join("fetch_webfilter.py"));
        }
        if let Some(backend_dir) = main_script.parent().and_then(|p| p.parent()) {
            candidates.push(backend_dir.join("src").join("fetch_webfilter.py"));
            candidates.push(backend_dir.join("fetch_webfilter.py"));
        }
    }

    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("backend").join("src").join("fetch_webfilter.py"));
        candidates.push(current.join("src-tauri").join("resources").join("backend").join("src").join("fetch_webfilter.py"));
        candidates.push(current.join("..").join("backend").join("src").join("fetch_webfilter.py"));
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join("backend").join("src").join("fetch_webfilter.py"));
        candidates.push(resource_dir.join("backend").join("fetch_webfilter.py"));
        candidates.push(
            resource_dir
                .join("resources")
                .join("backend")
                .join("src")
                .join("fetch_webfilter.py"),
        );
        candidates.push(
            resource_dir
                .join("resources")
                .join("backend")
                .join("fetch_webfilter.py"),
        );
    }

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    let tried = candidates
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<String>>()
        .join(" | ");

    Err(format!(
        "Could not locate backend/src/fetch_webfilter.py. Tried: {}",
        tried
    ))
}

#[tauri::command]
fn test_webfilter_login(app: tauri::AppHandle, payload: WebfilterPayload) -> Result<WebfilterResult, String> {
    let script_path = resolve_webfilter_script_path(&app)?;
    let msd_password = get_msd_password().unwrap_or(None);

    let mut command = Command::new(&payload.settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_MODE", "webfilter_test")
        .env("TFK_BASE_URL", &payload.settings.base_url)
        .env("PYTHONUNBUFFERED", "1");

    if !payload.settings.msd_username.trim().is_empty() {
        command.env("TFK_MSD_USERNAME", &payload.settings.msd_username);
    }
    if let Some(pw) = msd_password {
        command.env("TFK_MSD_PASSWORD", pw);
    }
    if payload.settings.debug {
        command.env("TFK_DEBUG", "1");
    }

    let output = command.output().map_err(|err| err.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Try to parse the last non-empty JSON line from stdout
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(result) = serde_json::from_str::<WebfilterResult>(trimmed) {
            return Ok(result);
        }
    }

    // No parseable JSON — return stderr as error message
    let err_msg = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        "No output from webfilter script".to_string()
    };
    Ok(WebfilterResult {
        ok: false,
        message: None,
        error: Some(err_msg),
        diag: None,
    })
}

#[tauri::command]
fn fetch_webfilter_logs(app: tauri::AppHandle, payload: WebfilterPayload) -> Result<WebfilterLogsResult, String> {
    let script_path = resolve_webfilter_script_path(&app)?;
    let msd_password = get_msd_password().unwrap_or(None);

    let mut command = Command::new(&payload.settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_MODE", "webfilter_logs")
        .env("TFK_BASE_URL", &payload.settings.base_url)
        .env("PYTHONUNBUFFERED", "1");

    if !payload.settings.msd_username.trim().is_empty() {
        command.env("TFK_MSD_USERNAME", &payload.settings.msd_username);
    }
    if let Some(pw) = msd_password {
        command.env("TFK_MSD_PASSWORD", pw);
    }
    if payload.settings.debug {
        command.env("TFK_DEBUG", "1");
    }

    let output = command.output().map_err(|err| err.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let debug_diag = if payload.settings.debug && !stderr.trim().is_empty() {
        Some(stderr.trim().to_string())
    } else {
        None
    };

    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(mut result) = serde_json::from_str::<WebfilterLogsResult>(trimmed) {
            if result.diag.is_none() {
                result.diag = debug_diag;
            }
            return Ok(result);
        }
    }

    let err_msg = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        "No output from webfilter logs script".to_string()
    };
    Ok(WebfilterLogsResult {
        ok: false,
        entries: vec![],
        error: Some(err_msg),
        diag: None,
    })
}

#[tauri::command]
fn fetch_webfilter_address_lists(
    app: tauri::AppHandle,
    payload: WebfilterPayload,
) -> Result<WebfilterAddressListsResult, String> {
    let script_path = resolve_webfilter_script_path(&app)?;
    let msd_password = get_msd_password().unwrap_or(None);

    let mut command = Command::new(&payload.settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_MODE", "webfilter_address_lists")
        .env("TFK_BASE_URL", &payload.settings.base_url)
        .env("PYTHONUNBUFFERED", "1");

    if !payload.settings.msd_username.trim().is_empty() {
        command.env("TFK_MSD_USERNAME", &payload.settings.msd_username);
    }
    if let Some(pw) = msd_password {
        command.env("TFK_MSD_PASSWORD", pw);
    }
    if payload.settings.debug {
        command.env("TFK_DEBUG", "1");
    }

    let output = command.output().map_err(|err| err.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let debug_diag = if payload.settings.debug && !stderr.trim().is_empty() {
        Some(stderr.trim().to_string())
    } else {
        None
    };

    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(mut result) = serde_json::from_str::<WebfilterAddressListsResult>(trimmed) {
            if result.diag.is_none() {
                result.diag = debug_diag;
            }
            return Ok(result);
        }
    }

    let err_msg = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        "No output from webfilter address-lists script".to_string()
    };

    Ok(WebfilterAddressListsResult {
        ok: false,
        whitelist_entries: vec![],
        blacklist_entries: vec![],
        whitelist_total: None,
        blacklist_total: None,
        error: Some(err_msg),
        diag: None,
    })
}

#[tauri::command]
fn write_webfilter_address_list(
    app: tauri::AppHandle,
    payload: WebfilterAddressListWritePayload,
) -> Result<WebfilterAddressListWriteResult, String> {
    let script_path = resolve_webfilter_script_path(&app)?;
    let msd_password = get_msd_password().unwrap_or(None);

    let mut command = Command::new(&payload.settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_MODE", "webfilter_address_list_write")
        .env("TFK_BASE_URL", &payload.settings.base_url)
        .env("TFK_WF_ACTION", &payload.action)
        .env("TFK_WF_LIST", &payload.list_type)
        .env("TFK_WF_ENTRY_ID", payload.entry_id.unwrap_or_default())
        .env("TFK_WF_ENTRY_NAME", payload.entry_name.unwrap_or_default())
        .env("TFK_WF_CURRENT_NAME", payload.current_name.unwrap_or_default())
        .env("TFK_WF_IDS", payload.entry_ids.join(","))
        .env("TFK_WF_IMPORT_TEXT", payload.import_text.unwrap_or_default())
        .env("PYTHONUNBUFFERED", "1");

    if !payload.settings.msd_username.trim().is_empty() {
        command.env("TFK_MSD_USERNAME", &payload.settings.msd_username);
    }
    if let Some(pw) = msd_password {
        command.env("TFK_MSD_PASSWORD", pw);
    }
    if payload.settings.debug {
        command.env("TFK_DEBUG", "1");
    }

    let output = command.output().map_err(|err| err.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let debug_diag = if payload.settings.debug && !stderr.trim().is_empty() {
        Some(stderr.trim().to_string())
    } else {
        None
    };

    let requested_save_path = payload.save_path.clone();

    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(mut result) = serde_json::from_str::<WebfilterAddressListWriteResult>(trimmed) {
            if result.ok {
                if let (Some(path), Some(content)) = (requested_save_path.as_ref(), result.export_content.as_ref()) {
                    fs::write(path, content).map_err(|err| err.to_string())?;
                    result.message = Some(format!(
                        "{} Saved to {}",
                        result.message.unwrap_or_else(|| "Export completed.".to_string()),
                        path
                    ));
                }
            }
            if result.diag.is_none() {
                result.diag = debug_diag;
            }
            return Ok(result);
        }
    }

    let err_msg = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        "No output from webfilter address-list write script".to_string()
    };

    Ok(WebfilterAddressListWriteResult {
        ok: false,
        message: None,
        error: Some(err_msg),
        diag: None,
        meta: None,
        export_content: None,
        export_filename: None,
        imported_lines: None,
        warnings: vec![],
    })
}

#[tauri::command]
async fn start_firewall_log_stream(
    app: tauri::AppHandle,
    settings: UiSettings,
) -> Result<(), String> {
    // Stop any previously running stream first
    {
        let state = app.state::<FirewallLogState>();
        let mut guard = state
            .child
            .lock()
            .map_err(|_| "FirewallLogState lock poisoned".to_string())?;
        if let Some(child) = guard.as_mut() {
            let _ = child.kill();
        }
        *guard = None;
    }

    let script_path = resolve_firewall_stream_script(&app)?;
    let config_path = app_data_file(&app, "last_run_settings.json")?;
    let config_raw = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(&config_path, config_raw).map_err(|e| e.to_string())?;

    let password = get_password().unwrap_or(None);

    let mut command = Command::new(&settings.python_path);
    command
        .arg("-u")
        .arg(&script_path)
        .env("TFK_SETTINGS_JSON", &config_path)
        .env("TFK_MODE", "firewall_stream")
        .env("PYTHONUNBUFFERED", "1");
    if !settings.username.trim().is_empty() {
        command.env("TFK_USERNAME", &settings.username);
    }
    if !settings.api_username.trim().is_empty() {
        command.env("TFK_API_USERNAME", &settings.api_username);
    }
    if !settings.api_key.trim().is_empty() {
        command.env("TFK_API_KEY", &settings.api_key);
    }
    if !settings.api_secret.trim().is_empty() {
        command.env("TFK_API_SECRET", &settings.api_secret);
    }
    if !settings.cookie_header.trim().is_empty() {
        command.env("TFK_COOKIE_HEADER", &settings.cookie_header);
    }
    if settings.debug {
        command.env("TFK_DEBUG", "1");
    }
    if let Some(pw) = password {
        command.env("TFK_PASSWORD", pw);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to spawn firewall log stream: {}", e))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "No stdout handle for firewall stream".to_string())?;

    // Store the child so we can kill it later
    {
        let state = app.state::<FirewallLogState>();
        let mut guard = state
            .child
            .lock()
            .map_err(|_| "FirewallLogState lock poisoned".to_string())?;
        *guard = Some(child);
    }

    // Spawn a background thread that reads JSON lines and emits Tauri events
    let app_clone = app.clone();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(text) => {
                    let trimmed = text.trim().to_string();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let _ = app_clone.emit("firewall-log-entry", trimmed);
                }
                Err(_) => break,
            }
        }
        let _ = app_clone.emit("firewall-log-stopped", ());
    });

    Ok(())
}

#[tauri::command]
fn stop_firewall_log_stream(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<FirewallLogState>();
    let mut guard = state
        .child
        .lock()
        .map_err(|_| "FirewallLogState lock poisoned".to_string())?;
    if let Some(child) = guard.as_mut() {
        let _ = child.kill();
    }
    *guard = None;
    let _ = app.emit("firewall-log-stopped", ());
    Ok(())
}

#[tauri::command]
fn cancel_run(app: tauri::AppHandle, state: tauri::State<ProcessState>) -> Result<(), String> {
    let mut guard = state.child.lock().map_err(|_| "Process lock poisoned".to_string())?;
    if let Some(child) = guard.as_mut() {
        let _ = child.kill();
        emit_line(&app, "Cancel requested.");
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(ProcessState::default())
        .manage(FirewallLogState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            run_dhcp,
            export_static,
            cancel_run,
            load_settings,
            save_settings,
            load_history,
            save_password,
            has_password,
            save_msd_password,
            has_msd_password,
            read_text_file,
            find_python,
            install_backend_deps,
            discover_api_credentials,
            load_dynamic_leases,
            move_dynamic_to_static,
            update_static_from_dynamic,
            start_firewall_log_stream,
            stop_firewall_log_stream,
            test_webfilter_login,
            fetch_webfilter_logs,
            fetch_webfilter_address_lists,
            write_webfilter_address_list
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
