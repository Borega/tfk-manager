import csv
import json
import os
import re
import sys
import tkinter as tk
import requests
from tkinter import simpledialog
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


BASE_DIR = Path(__file__).resolve().parent.parent
ENV_DATA_DIR = os.environ.get("TFK_DATA_DIR")
DATA_DIR = Path(ENV_DATA_DIR) if ENV_DATA_DIR else (BASE_DIR / "data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
CSV_PATH = DATA_DIR / "daten_template.csv"
LOG_PATH = DATA_DIR / "run_log.csv"
TEMP_CSV_PATH = DATA_DIR / "to_add.csv"
EXPORT_CSV_PATH = DATA_DIR / "export_static.csv"
DELETE_CSV_PATH = DATA_DIR / "to_delete.csv"
DEBUG = False
DRY_RUN = True  # Set False to submit entries
TIMEOUT_MS = 120000
ADD_BUTTON_TIMEOUT_MS = 10000
EDIT_DIALOG_TIMEOUT_MS = 15000
UPDATE_MODE_DEFAULT = "skip"  # "skip" or "update"
PROMPT_UPDATE_MODE = True
SLOW_MO_MS = 0
LAST_LEASE_SOURCE = "unknown"
LAST_LEASE_SOURCE_DETAIL = ""
SETTINGS_JSON_PATH: Optional[Path] = None
DEFAULT_IFACE = os.environ.get("TFK_IFACE", "lan")

BASE_URL = "https://<opnsense-host>"
LOGIN_URL = BASE_URL
DHCP_STATIC_URL = f"{BASE_URL.rstrip('/')}/ui/core/dashboard"
USERNAME: Optional[str] = None
PASSWORD: Optional[str] = None
API_USERNAME: Optional[str] = None
API_KEY: Optional[str] = None
API_SECRET: Optional[str] = None
COOKIE_HEADER: Optional[str] = None
MSD_COOKIE: Optional[str] = None


def load_settings_from_json() -> None:
    settings_path = os.environ.get("TFK_SETTINGS_JSON")
    if not settings_path:
        return
    global SETTINGS_JSON_PATH
    SETTINGS_JSON_PATH = Path(settings_path)
    try:
        with open(settings_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return

    def get_setting(payload: dict, snake: str, camel: str):
        if snake in payload:
            return payload.get(snake)
        return payload.get(camel)

    global BASE_URL, LOGIN_URL, DHCP_STATIC_URL, DRY_RUN, USERNAME, DEBUG
    global API_USERNAME, API_KEY, API_SECRET, COOKIE_HEADER, MSD_COOKIE
    configured_base_url = get_setting(data, "base_url", "baseUrl")
    if configured_base_url:
        BASE_URL = configured_base_url

    configured_login_url = get_setting(data, "login_url", "loginUrl")
    LOGIN_URL = configured_login_url or BASE_URL or LOGIN_URL

    configured_dashboard_url = get_setting(data, "dashboard_url", "dashboardUrl")
    if configured_dashboard_url:
        DHCP_STATIC_URL = configured_dashboard_url
    else:
        dashboard_base = (BASE_URL or LOGIN_URL).rstrip("/")
        DHCP_STATIC_URL = f"{dashboard_base}/ui/core/dashboard"
    DRY_RUN = get_setting(data, "dry_run", "dryRun") if ("dry_run" in data or "dryRun" in data) else DRY_RUN
    USERNAME = get_setting(data, "username", "username") or USERNAME
    API_USERNAME = get_setting(data, "api_username", "apiUsername") or API_USERNAME
    API_KEY = get_setting(data, "api_key", "apiKey") or API_KEY
    API_SECRET = get_setting(data, "api_secret", "apiSecret") or API_SECRET
    COOKIE_HEADER = get_setting(data, "cookie_header", "cookieHeader") or COOKIE_HEADER
    MSD_COOKIE = get_setting(data, "msd_cookie", "msdCookie") or MSD_COOKIE
    debug_setting = get_setting(data, "debug", "debug")
    if debug_setting is not None:
        if isinstance(debug_setting, str):
            DEBUG = debug_setting.strip().lower() in {"1", "true", "yes", "y"}
        else:
            DEBUG = bool(debug_setting)


def load_csv_path_from_env() -> None:
    incoming_path = os.environ.get("TFK_INCOMING_CSV")
    if not incoming_path:
        return
    path = Path(incoming_path)
    if path.exists():
        global CSV_PATH
        CSV_PATH = path


def load_delete_csv_path_from_env() -> None:
    delete_path = os.environ.get("TFK_DELETE_CSV")
    if not delete_path:
        return
    path = Path(delete_path)
    if path.exists():
        global DELETE_CSV_PATH
        DELETE_CSV_PATH = path


def load_credentials_from_env() -> None:
    global USERNAME, PASSWORD, DEBUG, API_USERNAME, API_KEY, API_SECRET, COOKIE_HEADER, MSD_COOKIE
    env_user = os.environ.get("TFK_USERNAME")
    env_pass = os.environ.get("TFK_PASSWORD")
    env_debug = os.environ.get("TFK_DEBUG")
    env_api_user = os.environ.get("TFK_API_USERNAME")
    env_api_key = os.environ.get("TFK_API_KEY")
    env_api_secret = os.environ.get("TFK_API_SECRET")
    env_cookie_header = os.environ.get("TFK_COOKIE_HEADER")
    env_msd_cookie = os.environ.get("TFK_MSD_COOKIE")
    if env_user:
        USERNAME = env_user
    if env_pass:
        PASSWORD = env_pass
    if env_api_user:
        API_USERNAME = env_api_user
    if env_api_key:
        API_KEY = env_api_key
    if env_api_secret:
        API_SECRET = env_api_secret
    if env_cookie_header:
        COOKIE_HEADER = env_cookie_header
    if env_msd_cookie:
        MSD_COOKIE = env_msd_cookie
    if env_debug is not None:
        DEBUG = env_debug.strip().lower() in {"1", "true", "yes", "y"}

MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")
IP_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)


@dataclass
class DhcpRow:
    hostname: str
    mac: str
    ip: str


def read_csv(path: Path) -> List[DhcpRow]:
    rows: List[DhcpRow] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=";")
        for idx, row in enumerate(reader, start=2):
            key_map = {k.lower(): k for k in row.keys() if k}
            hostname = (row.get(key_map.get("geraet", "")) or row.get(key_map.get("name", "")) or "").strip()
            mac = (row.get(key_map.get("mac", "")) or "").strip()
            ip = (row.get(key_map.get("ip", "")) or "").strip()
            if not hostname or not mac or not ip:
                print(f"Skip line {idx}: missing fields")
                continue
            rows.append(DhcpRow(hostname=hostname, mac=mac, ip=ip))
    return rows


def check_csv_format(path: Path) -> bool:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=";")
        headers = [h.lower() for h in (reader.fieldnames or [])]
        required = {"ip", "mac"}
        name_ok = "name" in headers or "geraet" in headers
        if not required.issubset(set(headers)) or not name_ok:
            print("CSV format invalid. Required columns: Name or Geraet, MAC, IP")
            return False
    return True


def validate_rows(rows: List[DhcpRow]) -> List[DhcpRow]:
    valid: List[DhcpRow] = []
    for row in rows:
        if not MAC_RE.match(row.mac):
            print(f"Invalid MAC: {row.mac} ({row.hostname})")
            continue
        if not IP_RE.match(row.ip):
            print(f"Invalid IP: {row.ip} ({row.hostname})")
            continue
        valid.append(row)
    return valid


def prompt_credentials() -> tuple[str, str]:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    username = simpledialog.askstring("OPNsense Login", "Username:")
    password = simpledialog.askstring("OPNsense Login", "Password:", show="*")
    root.destroy()

    if not username or not password:
        print("Login canceled.")
        sys.exit(1)
    return username, password


def prompt_update_mode() -> str:
    env_mode = os.environ.get("TFK_UPDATE_MODE", "").strip().lower()
    if env_mode in {"skip", "update"}:
        return env_mode
    if not PROMPT_UPDATE_MODE:
        return UPDATE_MODE_DEFAULT
    choice = input("Update mode on conflict? [skip/update] (default: skip): ").strip().lower()
    return "update" if choice == "update" else "skip"


def append_log(lines: List[str]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8", newline="") as handle:
        for line in lines:
            handle.write(line + "\n")


def get_effective_base_url() -> str:
    base = (BASE_URL or "").strip().rstrip("/")
    if base and "<" not in base and ">" not in base:
        return base
    return (LOGIN_URL or "").strip().rstrip("/")


def has_api_credentials() -> bool:
    return bool((API_KEY or "").strip() and (API_SECRET or "").strip())


class OPNsenseApiSession:
    def __init__(self, base_url: str, debug: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.debug = debug
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            }
        )
        self.csrf_token: Optional[str] = None

    def _log(self, message: str) -> None:
        if self.debug:
            print(f"DEBUG: {message}")

    def _apply_cookie_header(self, raw_cookie_header: str) -> None:
        if not raw_cookie_header.strip():
            return
        parsed_count = 0
        for part in raw_cookie_header.split(";"):
            item = part.strip()
            if not item or "=" not in item:
                continue
            name, value = item.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            self.session.cookies.set(name, value, path="/")
            parsed_count += 1
        self._log(f"Imported {parsed_count} cookie(s) from cookie header")

    def _capture_csrf_token(self, html: str) -> None:
        header_token = re.search(r'X-CSRFToken"\s*,\s*"([^\"]+)"', html)
        if header_token:
            self.csrf_token = header_token.group(1)
            return
        hidden_token = re.search(
            r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']',
            html,
            flags=re.IGNORECASE,
        )
        if hidden_token:
            self.csrf_token = hidden_token.group(1)

    @staticmethod
    def _is_login_page(html: str) -> bool:
        lowered = html.lower()
        return "anmelden" in lowered or 'id="usernamefld"' in lowered

    def _build_login_payload(self, login_html: str, username: str, password: str) -> Dict[str, str]:
        hidden_fields = dict(
            re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                login_html,
                flags=re.IGNORECASE,
            )
        )

        payload: Dict[str, str] = {}
        payload.update(hidden_fields)
        payload["usernamefld"] = username
        payload["passwordfld"] = password
        payload["login"] = "1"
        return payload

    def authenticate(self, username: str, password: str, cookie_header: str = "", msd_cookie: str = "") -> bool:
        login_page = self.session.get(f"{self.base_url}/", timeout=(30, 60), allow_redirects=True)
        self._capture_csrf_token(login_page.text)

        if cookie_header:
            self._apply_cookie_header(cookie_header)
        if msd_cookie:
            self.session.cookies.set("MSD_Cookie", msd_cookie, path="/")

        payload = self._build_login_payload(login_page.text, username, password)
        login_response = self.session.post(
            f"{self.base_url}/",
            data=payload,
            timeout=(30, 60),
            allow_redirects=False,
            headers={
                "Referer": f"{self.base_url}/",
                "Origin": self.base_url,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        self._log(
            "GUI login attempt "
            f"status={login_response.status_code} location={login_response.headers.get('Location', '')}"
        )

        if login_response.status_code in {301, 302, 303, 307, 308}:
            location = login_response.headers.get("Location", "/")
            if location.startswith("/"):
                location = f"{self.base_url}{location}"
            follow = self.session.get(location, timeout=(30, 60), allow_redirects=True)
            self._capture_csrf_token(follow.text)

        dashboard = self.session.get(
            f"{self.base_url}/ui/core/dashboard",
            timeout=(30, 60),
            allow_redirects=True,
        )
        self._capture_csrf_token(dashboard.text)
        ok = not self._is_login_page(dashboard.text)
        self._log(f"Authenticated session={ok}")
        return ok

    def _ajax_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.base_url}/ui/core/dashboard",
            "Origin": self.base_url,
        }
        if self.csrf_token:
            headers["X-CSRFToken"] = self.csrf_token
        return headers

    def api_get(self, endpoint: str) -> Dict[str, Any]:
        response = self.session.get(
            f"{self.base_url}{endpoint}",
            timeout=(30, 60),
            allow_redirects=True,
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{self.base_url}/ui/core/dashboard",
                "Origin": self.base_url,
            },
        )
        try:
            parsed = response.json()
            return {"ok": True, "http_status": response.status_code, "data": parsed}
        except json.JSONDecodeError:
            if self._is_login_page(response.text):
                return {"ok": False, "status": "unauthenticated", "http_status": response.status_code}
            return {"ok": False, "status": "non_json", "http_status": response.status_code, "text": response.text}

    def api_post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}{endpoint}",
            data=json.dumps(payload),
            timeout=(30, 60),
            headers=self._ajax_headers(),
        )
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                return parsed
            return {"status": "unknown", "response": parsed}
        except json.JSONDecodeError:
            if self._is_login_page(response.text):
                return {"status": "unauthenticated", "http_status": response.status_code}
            return {"status": "non_json", "http_status": response.status_code, "text": response.text}


def status_of_api_result(result: Dict[str, Any]) -> str:
    if not isinstance(result, dict):
        return "unknown"
    if "result" in result:
        lowered = str(result.get("result", "")).lower()
        if lowered == "ok":
            return "success"
        if lowered == "failed":
            return "failed"
    if "status" in result:
        return str(result.get("status", ""))
    return "success"


def initialize_api_session(username: str, password: str) -> Optional[OPNsenseApiSession]:
    base = get_effective_base_url()
    session = OPNsenseApiSession(base, debug=DEBUG)
    if not session.authenticate(username, password, cookie_header=COOKIE_HEADER or "", msd_cookie=MSD_COOKIE or ""):
        return None
    return session


def _walk_payload(node: Any):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_payload(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_payload(value)


def parse_api_user_information(payload: Any) -> tuple[Optional[str], Optional[str], Optional[str]]:
    username_keys = {"username", "user", "name", "apikeyname", "api_username", "apiusername"}
    key_keys = {"key", "apikey", "api_key", "token"}
    secret_keys = {"secret", "apisecret", "api_secret"}

    for item in _walk_payload(payload):
        item_ci = {str(key).lower(): value for key, value in item.items()}
        username = None
        key = None
        secret = None

        for candidate in username_keys:
            if candidate in item_ci and str(item_ci[candidate]).strip():
                username = str(item_ci[candidate]).strip()
                break
        for candidate in key_keys:
            if candidate in item_ci and str(item_ci[candidate]).strip():
                key = str(item_ci[candidate]).strip()
                break
        for candidate in secret_keys:
            if candidate in item_ci and str(item_ci[candidate]).strip():
                secret = str(item_ci[candidate]).strip()
                break

        if key and secret:
            return username, key, secret

    return None, None, None


def save_api_credentials_to_settings() -> None:
    if not SETTINGS_JSON_PATH or not SETTINGS_JSON_PATH.exists():
        return
    if not has_api_credentials():
        return
    try:
        with SETTINGS_JSON_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return

    if API_USERNAME:
        data["apiUsername"] = API_USERNAME
    data["apiKey"] = API_KEY
    data["apiSecret"] = API_SECRET

    try:
        with SETTINGS_JSON_PATH.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    except OSError:
        return


def refresh_api_credentials_via_session(session: OPNsenseApiSession) -> bool:
    global API_USERNAME, API_KEY, API_SECRET
    result = session.api_get("/api/tfk/dhcp/apiuserinformation")
    if not result.get("ok"):
        return False
    payload = result.get("data")
    api_username, api_key, api_secret = parse_api_user_information(payload)
    if not api_key or not api_secret:
        return False
    API_USERNAME = api_username or API_USERNAME
    API_KEY = api_key
    API_SECRET = api_secret
    save_api_credentials_to_settings()
    return True


def fetch_static_leases_via_direct_api() -> List[DhcpRow]:
    global LAST_LEASE_SOURCE_DETAIL
    if not has_api_credentials():
        LAST_LEASE_SOURCE_DETAIL = "direct-api missing credentials"
        return []

    base = get_effective_base_url()
    endpoints = [
        "/api/tfk/dhcp/static_leases",
        "/api/tfk/staticleases/get",
    ]

    auth_candidates: List[tuple[str, tuple[str, str]]] = []
    api_user = (API_USERNAME or "").strip()
    api_key = (API_KEY or "").strip()
    api_secret = (API_SECRET or "").strip()

    if api_key and api_secret:
        auth_candidates.append(("apiKey:apiSecret", (api_key, api_secret)))
    if api_user and api_secret:
        auth_candidates.append(("apiUsername:apiSecret", (api_user, api_secret)))
    if api_user and api_key:
        auth_candidates.append(("apiUsername:apiKey", (api_user, api_key)))

    seen_auths: set[tuple[str, str]] = set()
    deduped_auths: List[tuple[str, tuple[str, str]]] = []
    for label, auth in auth_candidates:
        if auth in seen_auths:
            continue
        seen_auths.add(auth)
        deduped_auths.append((label, auth))

    attempts: List[str] = []
    for endpoint in endpoints:
        url = f"{base}{endpoint}"
        for auth_label, auth in deduped_auths:
            try:
                response = requests.get(
                    url,
                    auth=auth,
                    verify=False,
                    timeout=(30, 60),
                    headers={"Accept": "application/json"},
                )
            except requests.RequestException as exc:
                attempts.append(f"{endpoint} {auth_label}=request-error:{exc}")
                continue

            if response.status_code != 200:
                attempts.append(f"{endpoint} {auth_label}=status:{response.status_code}")
                continue

            try:
                payload = response.json()
            except json.JSONDecodeError:
                attempts.append(f"{endpoint} {auth_label}=invalid-json")
                continue

            entries = _parse_static_leases_payload(payload)
            if entries:
                LAST_LEASE_SOURCE_DETAIL = (
                    f"direct-api endpoint={endpoint} auth={auth_label} entries={len(entries)}"
                )
                return entries

            payload_type = type(payload).__name__ if payload is not None else "none"
            attempts.append(f"{endpoint} {auth_label}=entries:0 payload:{payload_type}")

    LAST_LEASE_SOURCE_DETAIL = "direct-api failed; " + " | ".join(attempts[:6])
    return []


def _parse_static_leases_payload(payload: Any) -> List[DhcpRow]:
    entries: List[DhcpRow] = []
    seen: set[tuple[str, str, str]] = set()

    def add_entry(item: Any) -> None:
        if not isinstance(item, dict):
            return
        item_ci = {str(key).lower(): value for key, value in item.items()}
        hostname = str(item_ci.get("hostname") or item_ci.get("name") or "").strip()
        mac = str(item_ci.get("mac") or "").strip()
        ip = str(item_ci.get("ip") or item_ci.get("ipv4") or item_ci.get("address") or "").strip()
        if not hostname or not mac or not ip:
            return
        key = (hostname, mac, ip)
        if key in seen:
            return
        seen.add(key)
        entries.append(DhcpRow(hostname=hostname, mac=mac, ip=ip))

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            add_entry(node)
            for value in node.values():
                walk(value)
            return
        if isinstance(node, list):
            for value in node:
                walk(value)

    walk(payload)

    return entries


def fetch_static_leases_via_session_api(session: OPNsenseApiSession) -> List[DhcpRow]:
    global LAST_LEASE_SOURCE_DETAIL
    response = session.api_get("/api/tfk/dhcp/static_leases")
    if not response.get("ok"):
        LAST_LEASE_SOURCE_DETAIL = f"session-api failed status={response.get('status', 'unknown')}"
        return []

    payload = response.get("data")
    entries = _parse_static_leases_payload(payload)
    LAST_LEASE_SOURCE_DETAIL = f"session-api entries={len(entries)}"
    return entries


def find_conflict(existing: List[DhcpRow], row: DhcpRow) -> Optional[DhcpRow]:
    for item in existing:
        if row.mac == item.mac or row.ip == item.ip or row.hostname == item.hostname:
            return item
    return None


def write_temp_csv(rows: List[DhcpRow]) -> None:
    TEMP_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with TEMP_CSV_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(["Name", "MAC", "IP"])
        for row in rows:
            writer.writerow([row.hostname, row.mac, row.ip])


def export_static_leases(rows: List[DhcpRow]) -> None:
    EXPORT_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EXPORT_CSV_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(["Name", "MAC", "IP"])
        for row in rows:
            writer.writerow([row.hostname, row.mac, row.ip])


def summarize_changes(to_add: List[DhcpRow], to_update: List[Tuple[DhcpRow, DhcpRow]]) -> str:
    lines = []
    if to_add:
        lines.append("Add:")
        for row in to_add:
            lines.append(f"  + {row.hostname} {row.mac} {row.ip}")
    if to_update:
        lines.append("Update:")
        for incoming, existing in to_update:
            lines.append(
                f"  ~ {existing.hostname} {existing.mac} {existing.ip} "
                f"-> {incoming.hostname} {incoming.mac} {incoming.ip}"
            )
    if not lines:
        lines.append("No changes detected.")
    return "\n".join(lines)


def confirm_changes(summary: str) -> bool:
    env_confirm = os.environ.get("TFK_AUTO_CONFIRM", "").strip().lower()
    if env_confirm in {"1", "true", "yes", "y"}:
        print("Auto-confirm enabled. Proceeding.")
        print("Planned changes:")
        print(summary)
        return True
    print("Planned changes:")
    print(summary)
    choice = input("Proceed with these changes? [y/N]: ").strip().lower()
    return choice == "y"


def main() -> int:
    load_settings_from_json()
    load_csv_path_from_env()
    load_delete_csv_path_from_env()
    load_credentials_from_env()
    iface = os.environ.get("TFK_IFACE", DEFAULT_IFACE)

    username = USERNAME
    password = PASSWORD
    if not username or not password:
        username, password = prompt_credentials()

    api_session = initialize_api_session(username, password)
    if api_session is None:
        print("ERROR: Could not establish authenticated API session")
        return 1

    mode = os.environ.get("TFK_MODE", "").lower()
    if mode == "bootstrap_api":
        refreshed = refresh_api_credentials_via_session(api_session)
        if refreshed:
            print("API credentials refreshed from /api/tfk/dhcp/apiuserinformation")
            return 0
        print("Failed to refresh API credentials from /api/tfk/dhcp/apiuserinformation")
        return 1

    if mode == "export":
        global LAST_LEASE_SOURCE, LAST_LEASE_SOURCE_DETAIL
        LAST_LEASE_SOURCE = "unknown"
        LAST_LEASE_SOURCE_DETAIL = ""
        refresh_api_credentials_via_session(api_session)
        existing_entries = fetch_static_leases_via_session_api(api_session)
        LAST_LEASE_SOURCE = "api-session"
        export_static_leases(existing_entries)

        detail = LAST_LEASE_SOURCE_DETAIL or "n/a"
        append_log([
            f"-;-;-;info;lease source={LAST_LEASE_SOURCE}",
            f"-;-;-;info;lease source detail={detail}",
            f"-;-;-;info;mode=export;entries={len(existing_entries)}",
        ])
        print(f"Lease source: {LAST_LEASE_SOURCE}")
        print(f"Lease source detail: {detail}")
        print(f"Exported {len(existing_entries)} entries to {EXPORT_CSV_PATH}")
        return 0

    if not CSV_PATH.exists():
        print(f"CSV not found: {CSV_PATH}")
        return 1

    if not check_csv_format(CSV_PATH):
        return 1

    print(f"DEBUG: Using CSV at {CSV_PATH}") if DEBUG else None
    rows = validate_rows(read_csv(CSV_PATH))
    if not rows:
        print("No valid rows found.")
        return 1

    update_mode = prompt_update_mode()
    log_lines: List[str] = ["hostname;mac;ip;status;message"]

    refresh_api_credentials_via_session(api_session)
    existing_entries = fetch_static_leases_via_session_api(api_session)
    LAST_LEASE_SOURCE = "api-session"
    log_lines.append(f"-;-;-;info;lease source={LAST_LEASE_SOURCE}")
    export_static_leases(existing_entries)

    delete_rows: List[DhcpRow] = []
    if DELETE_CSV_PATH.exists():
        delete_rows = validate_rows(read_csv(DELETE_CSV_PATH))

    unique_rows: List[DhcpRow] = []
    seen_macs: set[str] = set()
    seen_ips: set[str] = set()
    seen_names: set[str] = set()

    for row in rows:
        if row.mac in seen_macs or row.ip in seen_ips or row.hostname in seen_names:
            log_lines.append(f"{row.hostname};{row.mac};{row.ip};skipped;duplicate in csv")
            continue
        seen_macs.add(row.mac)
        seen_ips.add(row.ip)
        seen_names.add(row.hostname)
        unique_rows.append(row)

    rows_to_add: List[DhcpRow] = []
    rows_to_update: List[Tuple[DhcpRow, DhcpRow]] = []
    for row in unique_rows:
        conflict = find_conflict(existing_entries, row)
        if conflict:
            if row.mac == conflict.mac and row.ip == conflict.ip and row.hostname == conflict.hostname:
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};skipped;exact match")
                continue
            if update_mode == "update":
                rows_to_update.append((row, conflict))
            else:
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};skipped;conflict exists")
            continue
        rows_to_add.append(row)

    write_temp_csv(rows_to_add)

    summary = summarize_changes(rows_to_add, rows_to_update)
    if not confirm_changes(summary):
        log_lines.append("-;-;-;skipped;user canceled")
        append_log(log_lines)
        print("Canceled by user.")
        return 0

    skipped_errors: List[Tuple[str, DhcpRow, str]] = []

    def record_item_error(action: str, row: DhcpRow, error_message: str) -> None:
        skipped_errors.append((action, row, error_message))
        log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;{action} {error_message}")

    if DRY_RUN:
        for row in delete_rows:
            log_lines.append(f"{row.hostname};{row.mac};{row.ip};ok;dry-run delete")
        for incoming_row, _existing_row in rows_to_update:
            log_lines.append(f"{incoming_row.hostname};{incoming_row.mac};{incoming_row.ip};ok;dry-run update")
        for row in rows_to_add:
            log_lines.append(f"{row.hostname};{row.mac};{row.ip};ok;dry-run add")
    else:
        for row in delete_rows:
            try:
                result = api_session.api_post(
                    "/api/tfk/dhcp/del_static_lease",
                    {"if": iface, "ip": row.ip, "mac": row.mac},
                )
                status = status_of_api_result(result)
                if status in {"failed", "validation_failed", "error", "unauthenticated", "non_json"}:
                    record_item_error("delete", row, status)
                    continue
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};ok;deleted")
            except Exception as exc:
                record_item_error("delete", row, f"exception: {exc}")

        for incoming_row, existing_row in rows_to_update:
            try:
                result = api_session.api_post(
                    "/api/tfk/dhcp/update_static_lease",
                    {
                        "if": iface,
                        "oldmac": existing_row.mac,
                        "ip": incoming_row.ip,
                        "mac": incoming_row.mac,
                        "hostname": incoming_row.hostname,
                    },
                )
                status = status_of_api_result(result)
                if status in {"failed", "validation_failed", "find_lease_failed", "error", "unauthenticated", "non_json"}:
                    record_item_error("update", incoming_row, status)
                    continue
                log_lines.append(f"{incoming_row.hostname};{incoming_row.mac};{incoming_row.ip};ok;updated")
            except Exception as exc:
                record_item_error("update", incoming_row, f"exception: {exc}")

        for row in rows_to_add:
            try:
                result = api_session.api_post(
                    "/api/tfk/dhcp/add_static_lease",
                    {"if": iface, "ip": row.ip, "mac": row.mac, "hostname": row.hostname},
                )
                status = status_of_api_result(result)
                if status in {"failed", "validation_failed", "error", "unauthenticated", "non_json"}:
                    record_item_error("add", row, status)
                    continue
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};ok;added")
            except Exception as exc:
                record_item_error("add", row, f"exception: {exc}")

    if skipped_errors:
        log_lines.append(f"-;-;-;info;skipped_errors={len(skipped_errors)}")
        print("Skipped items due to errors:")
        for action, row, error_message in skipped_errors:
            print(f"- {action.upper()} {row.hostname} {row.mac} {row.ip}: {error_message}")
        print(f"Total skipped due to errors: {len(skipped_errors)}")
    else:
        print("No items skipped due to API errors.")

    append_log(log_lines)
    print(f"Log written to {LOG_PATH}")

    if TEMP_CSV_PATH.exists():
        TEMP_CSV_PATH.unlink()
    if DELETE_CSV_PATH.exists():
        DELETE_CSV_PATH.unlink()

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
