#!/usr/bin/env python3
import html as html_lib
import json
import os
import re
import sys
from typing import Any, Dict, List
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
    fields: Dict[str, str] = {
        name: html_lib.unescape(value)
        for name, value in re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            html,
            flags=re.IGNORECASE,
        )
    }
    for raw_value, name in re.findall(
        r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    ):
        if name not in fields:
            fields[name] = html_lib.unescape(raw_value)
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


def discover_proxy_probe_path(html: str) -> str:
    # Prefer links that reference the Schulfilter handoff iframe/dashboard endpoint.
    for pattern in [
        r'href=["\']([^"\']*myiframe[^"\']*)["\']',
        r'href=["\']([^"\']*1920[^"\']*)["\']',
        r'href=["\']([^"\']*schulfilter[^"\']*)["\']',
        r'href=["\']([^"\']*sfp[^"\']*)["\']',
        r'href=["\']([^"\']*proxy[^"\']*)["\']',
    ]:
        match = re.search(pattern, html, flags=re.IGNORECASE)
        if match:
            return html_lib.unescape(match.group(1).strip())
    return ""


def discover_redirect_bridge_path(html: str) -> str:
    # SSO bridge is usually rendered as an iframe src=...redirect.php?&sID=...
    match = re.search(
        r'<iframe[^>]+src=["\']([^"\']*redirect\.php[^"\']*)["\']',
        html,
        flags=re.IGNORECASE,
    )
    if not match:
        return ""
    return html_lib.unescape(match.group(1).strip())


def msd_form_login(session: requests.Session, base_url: str, username: str, password: str) -> bool:
    """MSD-specific login flow: GET login page, scrape fields, POST authenticate."""
    if not username or not password:
        return False
    
    # Step 1: GET login page with username
    login_get_url = f"{base_url}/tfk.msd/login/login?username={username}"
    debug_log(f"GET {login_get_url}")
    try:
        login_page = session.get(login_get_url, timeout=(30, 60), allow_redirects=True)
        debug_log(f"GET status: {login_page.status_code}")
        if _debug_enabled():
            cookies_dict = {c.name: c.value for c in session.cookies}
            debug_log(f"Cookies after GET: {cookies_dict}")
    except requests.RequestException as exc:
        debug_log(f"Login GET failed: {exc}")
        return False
    
    # Step 2: Scrape hidden form fields with HTML-unescaped values.
    fields = extract_inputs(login_page.text)
    if not fields:
        debug_log("No form fields found in login page")
        return False
    
    hidden_fields = [name for name, val in fields.items() if name and not any(x in name.lower() for x in ['username', 'password'])]
    debug_log(f"Scraped hidden fields: {hidden_fields}")
    
    # Step 3: Add credentials and normalize ssoSession like the known-good flow.
    fields['username'] = username
    fields['password'] = password
    fields['ssoSession'] = ""
    
    # Step 4: POST to authenticate endpoint
    auth_url = f"{base_url}/tfk.msd/login/authenticate"
    debug_log(f"POST {auth_url}")
    try:
        auth_resp = session.post(
            auth_url,
            data=fields,
            timeout=(30, 60),
            allow_redirects=False,  # Handle redirect manually to track it
            headers={
                "Referer": login_get_url,
                "Origin": base_url,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        location = auth_resp.headers.get("Location", "")
        debug_log(f"POST status: {auth_resp.status_code}, Location: {location!r}")
        
        # Step 5: Follow redirect to dashboard
        if location:
            dashboard_url = urljoin(f"{base_url}/", location)
            debug_log(f"GET dashboard: {dashboard_url}")
            dashboard_resp = session.get(dashboard_url, timeout=(30, 60), allow_redirects=True)
            debug_log(f"Dashboard status: {dashboard_resp.status_code}, length: {len(dashboard_resp.text)}")
            return dashboard_resp.status_code == 200
        
        return auth_resp.status_code in (301, 302, 303, 307, 308)
    except requests.RequestException as exc:
        debug_log(f"Login POST failed: {exc}")
        return False


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

    landing = None  # Will be set by parent domain flow or direct connection
    dashboard_html = ""
    
    # Visit parent domain first to collect MSD_Cookie and MSD_Frontend
    # The proxy at :1920 requires cookies from the main MSD system
    parsed = urlsplit(base_url)
    if parsed.hostname:
        parent_url = f"{parsed.scheme}://{parsed.hostname}/"
        try:
            # Authenticate on parent domain if credentials provided
            if username and password:
                login_success = msd_form_login(session, parent_url.rstrip('/'), username, password)
                if not login_success:
                    return {
                        "ok": False,
                        "entries": [],
                        "error": "MSD login failed (authenticate did not return redirect)",
                    }
            
            # After login, get dashboard to find myiframe link
            dashboard_url = f"{parent_url.rstrip('/')}/tfk.msd/dashboard/index"
            debug_log(f"GET dashboard: {dashboard_url}")
            dashboard_resp = session.get(dashboard_url, timeout=(30, 60), allow_redirects=True)
            debug_log(f"Dashboard status: {dashboard_resp.status_code}, length: {len(dashboard_resp.text)}")
            dashboard_html = dashboard_resp.text

            dashboard_html = dashboard_resp.text

            # Follow browser bridge flow:
            # dashboard/myiframe -> iframe redirect.php?sID=... -> Location to :1920/dsh...sid...
            probe_path = discover_proxy_probe_path(dashboard_html)
            if not probe_path:
                # Fallback to default myiframe endpoint
                probe_path = "/tfk.msd/dashboard/myiframe?product_string=sfp"
            
            probe_url = urljoin(parent_url, probe_path)
            debug_log(f"Found Schulfilter Plus link: {probe_path}")
            debug_log(f"Probing Schulfilter Plus proxy at: {probe_url}")

            proxy_resp = session.get(
                probe_url,
                timeout=(30, 60),
                allow_redirects=True,
                headers={
                    "Referer": dashboard_url,
                    "DNT": "1",
                    "Upgrade-Insecure-Requests": "1",
                },
            )
            debug_log(f"Proxy probe response ({len(proxy_resp.text)} bytes): {proxy_resp.text[:300]!r}")

            redirect_path = discover_redirect_bridge_path(proxy_resp.text)
            if redirect_path:
                redirect_url = urljoin(parent_url, redirect_path)
                debug_log(f"GET redirect bridge: {redirect_url}")
                redirect_resp = session.get(
                    redirect_url,
                    timeout=(30, 60),
                    allow_redirects=False,
                    headers={
                        "Referer": probe_url,
                        "DNT": "1",
                        "Upgrade-Insecure-Requests": "1",
                    },
                )
                location_1920 = redirect_resp.headers.get("Location", "")
                debug_log(f"redirect.php status: {redirect_resp.status_code}, Location: {location_1920!r}")

                if location_1920:
                    handoff_url = location_1920
                    if not handoff_url.startswith("http"):
                        handoff_url = f"http://{parsed.hostname}:1920/{handoff_url.lstrip('/')}"
                    debug_log(f"Port-1920 handoff URL: {handoff_url}")
                    landing = session.get(
                        handoff_url,
                        timeout=(30, 60),
                        allow_redirects=True,
                        headers={
                            "Referer": f"{parent_url.rstrip('/')}/",
                            "DNT": "1",
                            "Upgrade-Insecure-Requests": "1",
                        },
                    )
                    debug_log(f"Cookies after handoff: {dict(session.cookies)}")
                    if _debug_enabled():
                        debug_log(f"All cookies: {dict(session.cookies)}")
        except requests.RequestException as exc:
            debug_log(f"Parent URL visit failed (non-fatal): {exc}")

    # If we didn't get landing from redirect.php, fetch proxy directly
    if landing is None:
        try:
            landing = session.get(f"{base_url}/", timeout=(30, 60), allow_redirects=True)
        except requests.RequestException as exc:
            return {"ok": False, "entries": [], "error": f"Webfilter connection failed: {exc}"}

    debug_log(f"Landing page status={landing.status_code} url={landing.url}")
    if _debug_enabled():
        cookies_after_landing = [f"{c.name}={c.value} (domain={c.domain}, path={c.path})" for c in session.cookies]
        debug_log(f"Cookies after landing: {', '.join(cookies_after_landing) if cookies_after_landing else '(none)'}")

    # Get the proxy base URL from landing URL (strip query params and path)
    landing_parsed = urlsplit(landing.url)
    proxy_base_url = f"{landing_parsed.scheme}://{landing_parsed.netloc}"
    
    # GET index.php entry page first (like working version does)
    entry_url = f"{proxy_base_url}/index.php"
    debug_log(f"GET entry page: {entry_url}")
    try:
        entry_resp = session.get(entry_url, timeout=(30, 60), allow_redirects=True)
        debug_log(f"GET entry status: {entry_resp.status_code}, length: {len(entry_resp.text)}, url: {entry_resp.url}")
    except requests.RequestException as exc:
        return {"ok": False, "entries": [], "error": f"Entry page request failed: {exc}"}
    
    # Build logs URL from entry page URL
    logs_url = f"{entry_resp.url.rsplit('?', 1)[0]}?action=logs"
    debug_log(f"Logs URL: {logs_url}")
    
    # GET logs page first
    try:
        logs_get_resp = session.get(logs_url, timeout=(30, 60), allow_redirects=True)
        debug_log(f"GET logs status: {logs_get_resp.status_code}, length: {len(logs_get_resp.text)}")
    except requests.RequestException as exc:
        return {"ok": False, "entries": [], "error": f"Logs GET request failed: {exc}"}

    # POST to logs with page size and filter
    form_data = {
        "sfpLogs[formFilterOld_freitext]": search_text,
        "sfpLogs[formPageOld]": "1",
        "sfpLogs[formPageSizeOld]": "25",
        "sfpLogs[formPageSizeTop]": "300",
        "sfpLogs[submitPageSizeTop]": "",
    }
    
    debug_log(f"POST {logs_url} (page_size=300)")
    if _debug_enabled():
        debug_log(f"POST payload keys: {list(form_data.keys())}")

    try:
        response = session.post(
            logs_url,
            data=form_data,
            timeout=(30, 60),
            allow_redirects=True,
            headers={
                "Referer": logs_url,
                "Origin": proxy_base_url,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
    except requests.RequestException as exc:
        return {"ok": False, "entries": [], "error": f"Webfilter logs request failed: {exc}"}

    debug_log(f"POST logs status: {response.status_code}, length: {len(response.text)}")

    if response.status_code >= 400:
        return {
            "ok": False,
            "entries": [],
            "error": f"Webfilter logs request failed with HTTP {response.status_code}",
        }

    entries = parse_log_entries(response.text)
    debug_log(f"Parsed {len(entries)} log entries")

    if not entries and _debug_enabled():
        debug_log("No webfilter log rows parsed from HTML response")
        # Save response HTML to temp file for debugging
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
            f.write(response.text)
            debug_log(f"Saved response HTML to: {f.name}")

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
