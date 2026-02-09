import csv
import json
import os
import re
import sys
import tkinter as tk
import time
from tkinter import simpledialog
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from playwright._impl._errors import TargetClosedError


BASE_DIR = Path(__file__).resolve().parent.parent
ENV_DATA_DIR = os.environ.get("TFK_DATA_DIR")
DATA_DIR = Path(ENV_DATA_DIR) if ENV_DATA_DIR else (BASE_DIR / "data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
CSV_PATH = DATA_DIR / "daten_template.csv"
LOG_PATH = DATA_DIR / "run_log.csv"
TEMP_CSV_PATH = DATA_DIR / "to_add.csv"
EXPORT_CSV_PATH = DATA_DIR / "export_static.csv"
DELETE_CSV_PATH = DATA_DIR / "to_delete.csv"
DEBUG = True
HEADLESS = False
DRY_RUN = True  # Set False to submit entries
TIMEOUT_MS = 120000
UPDATE_MODE_DEFAULT = "skip"  # "skip" or "update"
PROMPT_UPDATE_MODE = True
SLOW_MO_MS = 0

BASE_URL = "https://<opnsense-host>"
LOGIN_URL = "https://10.6.168.1:81"
DHCP_STATIC_URL = "https://10.6.168.1:81/ui/core/dashboard"
USERNAME: Optional[str] = None
PASSWORD: Optional[str] = None

# Replace these with stable selectors from your UI
SELECTORS: Dict[str, str] = {
    "username_input": "#usernamefld",
    "password_input": "#passwordfld",
    "login_button": ".btn",
    "dashboard_link": "#Lobby > a:nth-child(1) > div:nth-child(1) > div:nth-child(1) > div:nth-child(1)",
    "add_button": "button.btnAddLease[data-iface='lan']",
    "mac_input": "#input-mac",
    "ip_input": "#input-ip",
    "hostname_input": "#input-hostname",
    "save_button": ".btnSaveLease",
    # Optional:
    "search_input": "input[placeholder='Search']",
    "apply_button": "button:has-text('Apply')",
    "static_leases_table": "#statifdhcpleases-if-lease-table-lan",
    "edit_button": "button.btnEditLease",
    "cancel_edit_button": "button.btnCancelEditLease",
    "delete_button": "button.btnDelLease",
}


def load_settings_from_json() -> None:
    settings_path = os.environ.get("TFK_SETTINGS_JSON")
    if not settings_path:
        return
    try:
        with open(settings_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return

    def get_setting(payload: dict, snake: str, camel: str):
        if snake in payload:
            return payload.get(snake)
        return payload.get(camel)

    global BASE_URL, LOGIN_URL, DHCP_STATIC_URL, HEADLESS, DRY_RUN, USERNAME
    BASE_URL = get_setting(data, "base_url", "baseUrl") or BASE_URL
    LOGIN_URL = get_setting(data, "login_url", "loginUrl") or LOGIN_URL
    DHCP_STATIC_URL = get_setting(data, "dashboard_url", "dashboardUrl") or DHCP_STATIC_URL
    HEADLESS = get_setting(data, "headless", "headless") if "headless" in data else HEADLESS
    DRY_RUN = get_setting(data, "dry_run", "dryRun") if ("dry_run" in data or "dryRun" in data) else DRY_RUN
    USERNAME = get_setting(data, "username", "username") or USERNAME

    selectors = data.get("selectors") or {}
    SELECTORS.update({
        "add_button": selectors.get("add_button", selectors.get("addButton", SELECTORS["add_button"])),
        "edit_button": selectors.get("edit_button", selectors.get("editButton", SELECTORS["edit_button"])),
        "cancel_edit_button": selectors.get(
            "cancel_edit_button",
            selectors.get("cancelEditButton", SELECTORS["cancel_edit_button"]),
        ),
        "delete_button": selectors.get("delete_button", selectors.get("deleteButton", SELECTORS["delete_button"])),
    })


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
    global USERNAME, PASSWORD
    env_user = os.environ.get("TFK_USERNAME")
    env_pass = os.environ.get("TFK_PASSWORD")
    if env_user:
        USERNAME = env_user
    if env_pass:
        PASSWORD = env_pass

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


def safe_fill(page, selector: str, value: str) -> None:
    page.locator(selector).wait_for(timeout=TIMEOUT_MS)
    page.locator(selector).fill(value)


def optional_clear_search(page) -> None:
    search_selector = SELECTORS.get("search_input")
    if not search_selector:
        return
    try:
        locator = page.locator(search_selector)
        locator.wait_for(timeout=1000)
        locator.fill("")
    except PlaywrightTimeoutError:
        if DEBUG:
            print("DEBUG: search input not found, skipping clear")
        pass


def find_existing_by_mac(page, mac: str) -> bool:
    search_selector = SELECTORS.get("search_input")
    if not search_selector:
        return False
    try:
        locator = page.locator(search_selector)
        locator.wait_for(timeout=1000)
        locator.fill(mac)
        page.wait_for_timeout(500)
        return page.locator(f"text={mac}").first.is_visible()
    except PlaywrightTimeoutError:
        if DEBUG:
            print("DEBUG: search input not found, skipping existing check")
        return False


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


def login(page, username: str, password: str) -> None:
    page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=TIMEOUT_MS)
    safe_fill(page, SELECTORS["username_input"], username)
    safe_fill(page, SELECTORS["password_input"], password)
    page.locator(SELECTORS["login_button"]).click()
    page.wait_for_load_state("networkidle", timeout=TIMEOUT_MS * 4)


def open_dashboard(page) -> None:
    page.locator(SELECTORS["dashboard_link"]).click()
    page.wait_for_timeout(500)


def wait_for_edit_dialog_closed(page) -> None:
    cancel_selector = SELECTORS.get("cancel_edit_button")
    if not cancel_selector:
        return
    try:
        page.locator(cancel_selector).wait_for(state="hidden", timeout=TIMEOUT_MS)
    except PlaywrightTimeoutError:
        try:
            page.locator(cancel_selector).click()
            page.locator(cancel_selector).wait_for(state="hidden", timeout=TIMEOUT_MS)
        except PlaywrightTimeoutError:
            pass


def wait_for_add_button(page) -> None:
    add_selector = SELECTORS["add_button"]
    deadline = time.monotonic() + (TIMEOUT_MS * 6 / 1000)
    last_log = 0.0
    while time.monotonic() < deadline:
        try:
            if page.locator(add_selector).first.is_visible():
                if DEBUG:
                    print("DEBUG: add_button is visible")
                return
        except (PlaywrightTimeoutError, TargetClosedError):
            pass
        if DEBUG:
            now = time.monotonic()
            if now - last_log >= 5:
                elapsed = int(now - (deadline - (TIMEOUT_MS * 6 / 1000)))
                print(f"DEBUG: waiting for add_button... {elapsed}s")
                last_log = now
        time.sleep(1)
    raise PlaywrightTimeoutError(f"Add button not visible after {TIMEOUT_MS * 6}ms")


def open_dashboard_ready(page, username: str, password: str) -> None:
    login(page, username, password)
    open_dashboard(page)
    try:
        wait_for_add_button(page)
    except PlaywrightTimeoutError:
        if DEBUG:
            print("DEBUG: add_button not found on dashboard, navigating to DHCP_STATIC_URL")
        page.goto(DHCP_STATIC_URL, wait_until="domcontentloaded", timeout=TIMEOUT_MS)
        open_dashboard(page)
        wait_for_add_button(page)


def find_frame_with_selector(page, selector: str):
    for frame in page.frames:
        try:
            if frame.locator(selector).count() > 0:
                return frame
        except PlaywrightTimeoutError:
            continue
    return None


def add_mapping(page, row: DhcpRow) -> None:
    if DEBUG:
        print("DEBUG: add_mapping start")
    add_selector = SELECTORS["add_button"]
    add_locator = page.locator(add_selector)
    if not add_locator.is_visible():
        open_dashboard(page)
        wait_for_add_button(page)
    if DEBUG:
        print(f"DEBUG: add_button visible={add_locator.is_visible()} enabled={add_locator.is_enabled()}")

    if DEBUG:
        try:
            add_locator.highlight()
            box = add_locator.bounding_box()
            print(f"DEBUG: add_button box={box}")
        except PlaywrightTimeoutError:
            pass

    add_locator.scroll_into_view_if_needed()

    add_frame = find_frame_with_selector(page, add_selector)
    target = page
    if add_frame and add_frame != page.main_frame:
        if DEBUG:
            print(f"DEBUG: add_button found in iframe: {add_frame.url}")
        add_frame.locator(add_selector).click(trial=True)
        add_frame.locator(add_selector).click(force=True)
        target = add_frame
    else:
        add_locator.click(trial=True)
        add_locator.click(force=True)

    if DEBUG:
        print("DEBUG: add_button clicked, waiting for hostname input")

    target.locator(SELECTORS["hostname_input"]).wait_for(state="visible", timeout=TIMEOUT_MS)
    target.locator(SELECTORS["mac_input"]).wait_for(state="visible", timeout=TIMEOUT_MS)
    target.locator(SELECTORS["ip_input"]).wait_for(state="visible", timeout=TIMEOUT_MS)
    safe_fill(target, SELECTORS["mac_input"], row.mac)
    safe_fill(target, SELECTORS["ip_input"], row.ip)
    safe_fill(target, SELECTORS["hostname_input"], row.hostname)

    if DRY_RUN:
        print(f"DRY RUN: would save {row.hostname}")
        return

    page.locator(SELECTORS["save_button"]).click()
    page.wait_for_load_state("networkidle", timeout=TIMEOUT_MS)


def apply_changes(page) -> None:
    apply_selector = SELECTORS.get("apply_button")
    if not apply_selector:
        return
    try:
        page.locator(apply_selector).click()
        page.wait_for_load_state("networkidle", timeout=TIMEOUT_MS)
    except PlaywrightTimeoutError:
        pass


def append_log(lines: List[str]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8", newline="") as handle:
        for line in lines:
            handle.write(line + "\n")


def get_existing_entries(page) -> List[DhcpRow]:
    table_selector = SELECTORS.get("static_leases_table")
    if not table_selector:
        return []
    try:
        table = page.locator(table_selector)
        table.wait_for(timeout=5000)
        edit_selector = SELECTORS.get("edit_button")
        buttons = table.locator(edit_selector) if edit_selector else table.locator("tbody tr")
        count = buttons.count()
    except PlaywrightTimeoutError:
        if DEBUG:
            print("DEBUG: static leases table not found for existing check")
        return []

    existing: List[DhcpRow] = []
    for i in range(count):
        row = buttons.nth(i)
        try:
            hostname = row.get_attribute("data-hostname") or ""
            mac = row.get_attribute("data-mac") or ""
            ip = row.get_attribute("data-ip") or ""
            if hostname and mac and ip:
                existing.append(DhcpRow(hostname=hostname, mac=mac, ip=ip))
                continue

            cells = row.locator("td").all_inner_texts()
            row_text = " ".join(cells) if cells else row.inner_text()
        except PlaywrightTimeoutError:
            continue

        mac_match = MAC_RE.search(row_text)
        ip_match = IP_RE.search(row_text)
        hostname = (cells[0].strip() if cells else "")
        if mac_match and ip_match and hostname:
            existing.append(DhcpRow(hostname=hostname, mac=mac_match.group(0), ip=ip_match.group(0)))
    return existing


def find_conflict(existing: List[DhcpRow], row: DhcpRow) -> Optional[DhcpRow]:
    for item in existing:
        if row.mac == item.mac or row.ip == item.ip or row.hostname == item.hostname:
            return item
    return None


def wait_for_delete_gone(page, row: DhcpRow) -> bool:
    table_selector = SELECTORS.get("static_leases_table")
    delete_selector = SELECTORS.get("delete_button")
    if not table_selector or not delete_selector:
        return False

    table = page.locator(table_selector)
    deadline = time.monotonic() + (TIMEOUT_MS / 1000)
    while time.monotonic() < deadline:
        try:
            locator = table.locator(f"{delete_selector}[data-mac='{row.mac}']")
            if locator.count() == 0:
                locator = table.locator(f"{delete_selector}[data-ip='{row.ip}']")
            if locator.count() == 0:
                locator = table.locator(f"{delete_selector}[data-hostname='{row.hostname}']")
            if locator.count() == 0 or not locator.first.is_visible():
                return True
        except PlaywrightTimeoutError:
            pass
        page.wait_for_timeout(500)
    return False


def delete_mapping(page, row: DhcpRow) -> bool:
    table_selector = SELECTORS.get("static_leases_table")
    delete_selector = SELECTORS.get("delete_button")
    if not table_selector or not delete_selector:
        return False

    table = page.locator(table_selector)
    table.wait_for(timeout=5000)
    delete_button = table.locator(f"{delete_selector}[data-mac='{row.mac}']").first
    if delete_button.count() == 0:
        delete_button = table.locator(f"{delete_selector}[data-ip='{row.ip}']").first
    if delete_button.count() == 0:
        delete_button = table.locator(f"{delete_selector}[data-hostname='{row.hostname}']").first
    if delete_button.count() == 0:
        return False

    if DRY_RUN:
        print(f"DRY RUN: would delete {row.hostname} {row.mac} {row.ip}")
        return True

    page.once("dialog", lambda dialog: dialog.accept())
    delete_button.click()
    page.wait_for_load_state("networkidle", timeout=TIMEOUT_MS)
    return wait_for_delete_gone(page, row)


def update_mapping(page, row: DhcpRow) -> bool:
    table_selector = SELECTORS.get("static_leases_table")
    edit_selector = SELECTORS.get("edit_button")
    if not table_selector or not edit_selector:
        return False

    table = page.locator(table_selector)
    table.wait_for(timeout=5000)
    edit_button = table.locator(f"{edit_selector}[data-mac='{row.mac}']").first
    if edit_button.count() == 0:
        edit_button = table.locator(f"{edit_selector}[data-ip='{row.ip}']").first
    if edit_button.count() == 0:
        edit_button = table.locator(f"{edit_selector}[data-hostname='{row.hostname}']").first
    if edit_button.count() == 0:
        return False

    edit_button.click()
    page.locator(SELECTORS["hostname_input"]).wait_for(state="visible", timeout=TIMEOUT_MS)
    safe_fill(page, SELECTORS["mac_input"], row.mac)
    safe_fill(page, SELECTORS["ip_input"], row.ip)
    safe_fill(page, SELECTORS["hostname_input"], row.hostname)

    if DRY_RUN:
        page.locator(SELECTORS["cancel_edit_button"]).click()
        wait_for_edit_dialog_closed(page)
        return True

    page.locator(SELECTORS["save_button"]).click()
    page.wait_for_load_state("networkidle", timeout=TIMEOUT_MS)
    wait_for_edit_dialog_closed(page)
    return True


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


def summarize_changes(to_add: List[DhcpRow], to_update: List[DhcpRow]) -> str:
    lines = []
    if to_add:
        lines.append("Add:")
        for row in to_add:
            lines.append(f"  + {row.hostname} {row.mac} {row.ip}")
    if to_update:
        lines.append("Update:")
        for row in to_update:
            lines.append(f"  ~ {row.hostname} {row.mac} {row.ip}")
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
    if os.environ.get("TFK_MODE", "").lower() == "export":
        if not USERNAME or not PASSWORD:
            username, password = prompt_credentials()
        else:
            username, password = USERNAME, PASSWORD

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=HEADLESS, slow_mo=SLOW_MO_MS, args=[
                "--disable-extensions",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-sandbox",
                "--start-maximized",
            ])
            context = browser.new_context(ignore_https_errors=True, viewport=None)

            existing_entries: List[DhcpRow] = []
            last_error: Optional[Exception] = None
            for _ in range(2):
                page = context.new_page()
                page.bring_to_front()
                page.set_default_timeout(TIMEOUT_MS)
                page.set_default_navigation_timeout(TIMEOUT_MS)
                try:
                    open_dashboard_ready(page, username, password)
                    existing_entries = get_existing_entries(page)
                    export_static_leases(existing_entries)
                    last_error = None
                    break
                except (PlaywrightTimeoutError, TargetClosedError) as exc:
                    last_error = exc
                    try:
                        page.close()
                    except Exception:
                        pass
                    continue

            context.close()
            browser.close()

            if last_error is not None:
                print(f"ERROR: export failed: {last_error}")
                return 1

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

    username = USERNAME
    password = PASSWORD
    if not username or not password:
        username, password = prompt_credentials()

    update_mode = prompt_update_mode()

    print(f"DEBUG: Starting browser (headless={HEADLESS})") if DEBUG else None
    log_lines: List[str] = ["hostname;mac;ip;status;message"]
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS, slow_mo=SLOW_MO_MS, args=[
            "--disable-extensions",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--no-sandbox",
            "--start-maximized",
        ])
        context = browser.new_context(ignore_https_errors=True, viewport=None)
        page = context.new_page()
        page.bring_to_front()
        page.set_default_timeout(TIMEOUT_MS)
        page.set_default_navigation_timeout(TIMEOUT_MS)

        print("DEBUG: Logging in...") if DEBUG else None
        login(page, username, password)
        print("DEBUG: Opening dashboard...") if DEBUG else None
        open_dashboard(page)
        print("DEBUG: Waiting for DHCP widget...") if DEBUG else None
        try:
            wait_for_add_button(page)
        except PlaywrightTimeoutError:
            print("DEBUG: DHCP widget not visible yet, navigating to dashboard...") if DEBUG else None
            page.goto(DHCP_STATIC_URL, wait_until="domcontentloaded", timeout=TIMEOUT_MS)
            open_dashboard(page)
            wait_for_add_button(page)

        existing_entries = get_existing_entries(page)
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
        rows_to_update: List[DhcpRow] = []
        for row in unique_rows:
            conflict = find_conflict(existing_entries, row)
            if conflict:
                if row.mac == conflict.mac and row.ip == conflict.ip and row.hostname == conflict.hostname:
                    log_lines.append(f"{row.hostname};{row.mac};{row.ip};skipped;exact match")
                    continue
                if update_mode == "update":
                    rows_to_update.append(row)
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

        for row in rows_to_update:
            print(f"DEBUG: Updating {row.hostname} {row.mac} {row.ip}") if DEBUG else None
            try:
                if update_mapping(page, row):
                    log_lines.append(f"{row.hostname};{row.mac};{row.ip};ok;updated")
                else:
                    log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;update selector missing")
            except PlaywrightTimeoutError as exc:
                print(f"ERROR: update timeout for {row.hostname}: {exc}")
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;update timeout")
                continue

        for row in delete_rows:
            print(f"DEBUG: Deleting {row.hostname} {row.mac} {row.ip}") if DEBUG else None
            try:
                if delete_mapping(page, row):
                    log_lines.append(f"{row.hostname};{row.mac};{row.ip};ok;deleted")
                else:
                    log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;delete selector missing")
            except PlaywrightTimeoutError as exc:
                print(f"ERROR: delete timeout for {row.hostname}: {exc}")
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;delete timeout")
                continue
            except Exception as exc:
                print(f"ERROR: delete failed for {row.hostname}: {exc}")
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;{exc}")
                continue
            except Exception as exc:
                print(f"ERROR: update failed for {row.hostname}: {exc}")
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;{exc}")
                continue

        for row in rows_to_add:
            print(f"DEBUG: Processing {row.hostname} {row.mac} {row.ip}") if DEBUG else None
            optional_clear_search(page)
            if find_existing_by_mac(page, row.mac):
                print(f"Skip existing MAC: {row.mac} ({row.hostname})")
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};skipped;mac exists")
                continue
            try:
                add_mapping(page, row)
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};ok;added")
            except PlaywrightTimeoutError as exc:
                print(f"ERROR: add_mapping timeout for {row.hostname}: {exc}")
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;timeout")
                continue
            except Exception as exc:
                print(f"ERROR: add_mapping failed for {row.hostname}: {exc}")
                log_lines.append(f"{row.hostname};{row.mac};{row.ip};fail;{exc}")
                continue

        if not DRY_RUN:
            apply_changes(page)

        context.close()
        browser.close()

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
