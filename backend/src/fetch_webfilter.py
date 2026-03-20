#!/usr/bin/env python3
import html as html_lib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def _debug_enabled() -> bool:
    return os.environ.get("TFK_DEBUG", "").strip() in {"1", "true", "yes", "y"}


def debug_log(message: str) -> None:
    if _debug_enabled():
        print(f"DEBUG: {message}", file=sys.stderr, flush=True)


def normalize_base_url(base_url: str) -> str:
    trimmed = (base_url or "").strip()
    if not trimmed:
        return ""
    try:
        parsed = urlsplit(trimmed)
    except ValueError:
        return trimmed.rstrip("/")

    if not parsed.scheme or not parsed.netloc or not parsed.hostname:
        return trimmed.rstrip("/")

    host = parsed.hostname
    host_display = f"[{host}]" if ":" in host else host
    auth = ""
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        auth = f"{auth}@"

    netloc = f"{auth}{host_display}:81"
    normalized = urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/"), parsed.query, parsed.fragment))
    return normalized.rstrip("/")


def derive_msd_base_url(base_url: str) -> str:
    normalized = normalize_base_url(base_url)
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    if not parsed.hostname:
        return ""

    host_display = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    auth = ""
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        auth = f"{auth}@"

    # Schulfilter Plus is served on :1920 and commonly over HTTP.
    netloc = f"{auth}{host_display}:1920"
    return urlunsplit(("http", netloc, "", "", "")).rstrip("/")


def apply_cookie_header(session: requests.Session, cookie_header: str) -> int:
    count = 0
    for part in (cookie_header or "").split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        session.cookies.set(name, value, path="/")
        count += 1
    return count


def extract_inputs(html: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    input_pattern = re.compile(
        r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*>",
        flags=re.IGNORECASE,
    )
    value_pattern = re.compile(r"value=[\"']([^\"']*)[\"']", flags=re.IGNORECASE)
    for match in input_pattern.finditer(html):
        full_tag = match.group(0)
        name = match.group(1)
        value_match = value_pattern.search(full_tag)
        value = value_match.group(1) if value_match else ""
        fields[name] = value
    return fields


def discover_logs_path(html: str, fallback_path: str = "") -> str:
    # Prefer explicit links/forms that include action=logs.
    link_match = re.search(
        r"(?:href|action)=[\"']([^\"']*\?action=logs[^\"']*)[\"']",
        html,
        flags=re.IGNORECASE,
    )
    if link_match:
        candidate = html_lib.unescape(link_match.group(1).strip())
        if candidate.startswith("http://") or candidate.startswith("https://"):
            split = urlsplit(candidate)
            return urlunsplit(("", "", split.path, split.query, ""))
        return candidate

    if fallback_path:
        split = urlsplit(fallback_path)
        query = parse_qs(split.query)
        query_action = query.get("action", [""])[0].lower()
        if query_action == "logs":
            return urlunsplit(("", "", split.path, split.query, ""))
        if split.path:
            return f"{split.path}?action=logs"

    return "/?action=logs"


def try_form_login(session: requests.Session, base_url: str, html: str, username: str, password: str) -> None:
    if not username or not password:
        return

    fields = extract_inputs(html)
    if not fields:
        return

    user_field: Optional[str] = None
    pass_field: Optional[str] = None
    for name in fields.keys():
        lowered = name.lower()
        if user_field is None and ("user" in lowered or "login" in lowered):
            user_field = name
        if pass_field is None and "pass" in lowered:
            pass_field = name

    if not user_field or not pass_field:
        return

    fields[user_field] = username
    fields[pass_field] = password
    fields.setdefault("login", "1")

    action_match = re.search(r"<form[^>]*action=[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE)
    action = action_match.group(1).strip() if action_match else "/"
    login_url = urljoin(f"{base_url}/", action)
    debug_log(f"Submitting login form to {login_url}")

    response = session.post(
        login_url,
        data=fields,
        timeout=(30, 60),
        allow_redirects=True,
        headers={
            "Referer": f"{base_url}/",
            "Origin": base_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    debug_log(f"Login form response status={response.status_code} url={response.url}")


def parse_log_entries(html: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    row_pattern = re.compile(r"<tr[^>]*>(.*?)</tr>", flags=re.IGNORECASE | re.DOTALL)
    cell_pattern = re.compile(r"<t[dh][^>]*>(.*?)</t[dh]>", flags=re.IGNORECASE | re.DOTALL)
    tag_pattern = re.compile(r"<[^>]+>")

    for row_match in row_pattern.finditer(html):
        row_html = row_match.group(1)
        cells = cell_pattern.findall(row_html)
        if len(cells) < 6:
            continue

        cleaned: List[str] = []
        for cell in cells[:6]:
            no_tags = tag_pattern.sub(" ", cell)
            text = html_lib.unescape(" ".join(no_tags.split())).strip()
            cleaned.append(text)

        # Skip header-like rows.
        if cleaned[0].lower() in {"action", "aktion"}:
            continue

        entries.append(
            {
                "action": cleaned[0],
                "user": cleaned[1],
                "ip": cleaned[2],
                "time": cleaned[3],
                "url": cleaned[4],
                "category": cleaned[5],
            }
        )

    return entries


def fetch_webfilter_logs(search_text: str) -> Dict[str, Any]:
    base_url = derive_msd_base_url(os.environ.get("TFK_BASE_URL", ""))
    if not base_url:
        return {"ok": False, "entries": [], "error": "Base URL is not configured"}

    session = requests.Session()
    session.verify = False
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
        }
    )

    raw_cookie_header = os.environ.get("TFK_COOKIE_HEADER", "")
    imported = apply_cookie_header(session, raw_cookie_header)
    if imported:
        debug_log(f"Imported {imported} cookie(s) from TFK_COOKIE_HEADER")

    username = os.environ.get("TFK_MSD_USERNAME", "").strip()
    password = os.environ.get("TFK_MSD_PASSWORD", "").strip()

    try:
        landing = session.get(f"{base_url}/", timeout=(30, 60), allow_redirects=True)
    except requests.RequestException as exc:
        return {"ok": False, "entries": [], "error": f"Webfilter connection failed: {exc}"}

    debug_log(f"Landing page status={landing.status_code} url={landing.url}")
    try_form_login(session, base_url, landing.text, username, password)

    logs_path = discover_logs_path(landing.text, urlsplit(landing.url).path)
    logs_url = urljoin(f"{base_url}/", logs_path.lstrip("/"))
    if "action=logs" not in logs_url:
        joiner = "&" if "?" in logs_url else "?"
        logs_url = f"{logs_url}{joiner}action=logs"

    debug_log(f"Logs endpoint={logs_url}")

    form_data = {
        "sfpLogs[formPageSizeOld]": "25",
        "sfpLogs[formPageOld]": "1",
        "sfpLogs[formFilterOld_freitext]": "",
        "sfpLogs[formPageSizeTop]": "50",
        "sfpLogs[formFilter_freitext]": search_text,
        "sfpLogs[submit_filter_freitext]": "Filtern",
        "sfpLogs[formPageSizeBottom]": "50",
    }

    try:
        response = session.post(
            logs_url,
            data=form_data,
            timeout=(30, 60),
            allow_redirects=True,
            headers={
                "Referer": logs_url,
                "Origin": base_url,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
    except requests.RequestException as exc:
        return {"ok": False, "entries": [], "error": f"Webfilter logs request failed: {exc}"}

    if response.status_code >= 400:
        return {
            "ok": False,
            "entries": [],
            "error": f"Webfilter logs request failed with HTTP {response.status_code}",
        }

    entries = parse_log_entries(response.text)
    if not entries and _debug_enabled():
        debug_log("No webfilter log rows parsed from HTML response")

    return {
        "ok": True,
        "entries": entries,
        "parameter": {
            "filter": "all",
        },
    }


def run_webfilter_test() -> Dict[str, Any]:
    result = fetch_webfilter_logs("")
    if result.get("ok"):
        return {"ok": True, "message": "Webfilter login/session is usable"}
    return {"ok": False, "error": result.get("error") or "Webfilter test failed"}


def main() -> int:
    mode = os.environ.get("TFK_MODE", "").strip().lower()
    if mode == "webfilter_test":
        print(json.dumps(run_webfilter_test(), ensure_ascii=False))
        return 0

    if mode == "webfilter_logs":
        search_text = os.environ.get("TFK_WEBFILTER_LOG_SEARCH", "")
        print(json.dumps(fetch_webfilter_logs(search_text), ensure_ascii=False))
        return 0

    if mode == "webfilter_address_lists":
        print(
            json.dumps(
                {
                    "ok": False,
                    "whitelistEntries": [],
                    "blacklistEntries": [],
                    "error": "Webfilter address-list mode is not available in this backend script yet",
                },
                ensure_ascii=False,
            )
        )
        return 1

    if mode == "webfilter_address_list_write":
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "Webfilter address-list write mode is not available in this backend script yet",
                    "warnings": [],
                },
                ensure_ascii=False,
            )
        )
        return 1

    print(json.dumps({"ok": False, "error": f"Unsupported mode: {mode}"}, ensure_ascii=False))
    return 1


if __name__ == "__main__":
    sys.exit(main())
