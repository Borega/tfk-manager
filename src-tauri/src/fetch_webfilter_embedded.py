#!/usr/bin/env python3
"""
MSD web filter management (port 80, http://host/tfk.msd/...)

Handles session-based login with CSRF token scraping for the MSD system.
After login the session is reused to fetch the Schulfilter Plus filter log
from the proxy management interface (port 1920).

Env vars:
    TFK_MSD_USERNAME   - username for the MSD web UI (port 80)
    TFK_MSD_PASSWORD   - password for the MSD web UI (port 80)
    TFK_BASE_URL       - OPNsense base URL (e.g. https://your-opnsense-host:81)
    TFK_MODE           - operation: webfilter_test | webfilter_logs | webfilter_address_lists | webfilter_address_list_write
    TFK_WF_ACTION      - address list write action: add | edit | delete | import | export
    TFK_WF_LIST        - target list: wl | bl | whitelist | blacklist
    TFK_WF_ENTRY_ID    - entry id for edit
    TFK_WF_ENTRY_NAME  - entry value for add/edit
    TFK_WF_CURRENT_NAME- current entry value for edit duplicate-check short-circuit
    TFK_WF_IDS         - comma-separated entry ids for delete
    TFK_WF_IMPORT_TEXT - newline separated entries for import
    TFK_DEBUG          - enable debug logging if set to 1/true
"""

import json
import os
import re
import sys
from html import unescape as html_unescape

import requests
from urllib.parse import parse_qs, urlsplit
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

MSD_USERNAME: str = os.environ.get("TFK_MSD_USERNAME", "")
MSD_PASSWORD: str = os.environ.get("TFK_MSD_PASSWORD", "")
BASE_URL: str = os.environ.get("TFK_BASE_URL", "")
TFK_MODE: str = os.environ.get("TFK_MODE", "webfilter_test")
TFK_WF_ACTION: str = os.environ.get("TFK_WF_ACTION", "")
TFK_WF_LIST: str = os.environ.get("TFK_WF_LIST", "")
TFK_WF_ENTRY_ID: str = os.environ.get("TFK_WF_ENTRY_ID", "")
TFK_WF_ENTRY_NAME: str = os.environ.get("TFK_WF_ENTRY_NAME", "")
TFK_WF_CURRENT_NAME: str = os.environ.get("TFK_WF_CURRENT_NAME", "")
TFK_WF_IDS: str = os.environ.get("TFK_WF_IDS", "")
TFK_WF_IMPORT_TEXT: str = os.environ.get("TFK_WF_IMPORT_TEXT", "")
DEBUG: bool = os.environ.get("TFK_DEBUG", "").strip().lower() in {"1", "true", "yes", "y"}


def get_msd_base_url(base_url: str) -> str:
    """Derive the MSD base URL (plain HTTP, port 80) from the OPNsense base URL."""
    stripped = (base_url or "").strip()
    if not stripped:
        return ""
    try:
        parsed = urlsplit(stripped)
        host = parsed.hostname or ""
        if not host:
            return ""
        return f"http://{host}"
    except Exception:
        return ""


class MsdSession:
    def __init__(self, msd_base_url: str, debug: bool = False) -> None:
        self.base_url = msd_base_url.rstrip("/")
        self.debug = debug
        # proxy_base_url is set after successful login by following the post-login redirect
        self.proxy_base_url: str = ""
        self.proxy_probe_url: str = ""  # original un-redirected probe URL
        self.proxy_handoff_url: str = ""  # dynamic /dsh...sid... URL from redirect.php
        self.proxy_installation: str = ""
        self.proxy_product_string: str = "sfp"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) "
                "Gecko/20100101 Firefox/148.0"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        })

    def _log(self, msg: str) -> None:
        if self.debug:
            print(f"DEBUG: {msg}", file=sys.stderr)

    def _build_proxy_cookie_header(self) -> str:
        """Build a stable Cookie header for proxy requests regardless of cookie path/domain."""
        values: dict[str, str] = {}
        for cookie in self.session.cookies:
            if cookie.name in {"MSD_Cookie", "MSD_Frontend", "msdproxy"} and cookie.value:
                values[cookie.name] = cookie.value

        parts = []
        for name in ("MSD_Cookie", "MSD_Frontend", "msdproxy"):
            value = values.get(name)
            if value:
                parts.append(f"{name}={value}")
        return "; ".join(parts)

    def _scrape_hidden_fields(self, html: str) -> dict:
        """
        Extract all hidden input fields from an HTML page.

        HTML-unescapes captured values so that e.g. &quot; becomes "
        before submission — required for CSRF tokens that contain serialised
        PHP strings with double-quote characters.
        """
        fields = {
            name: html_unescape(value)
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
                fields[name] = html_unescape(raw_value)
        return fields

    def authenticate(self, username: str, password: str) -> dict:
        """
        Authenticate against the MSD system and follow the post-login redirect
        to collect all session cookies (MSD_Cookie, MSD_Frontend, msdproxy).

        The redirect target URL (e.g. http://10.6.168.1:1920/) is stored as
        self.proxy_base_url for subsequent requests.

        Returns a dict with 'ok' and either 'message' or 'error'+'diag'.
        """
        login_get_url = f"{self.base_url}/tfk.msd/login/login?username={username}"
        self._log(f"GET {login_get_url}")

        try:
            get_resp = self.session.get(login_get_url, timeout=(30, 60), allow_redirects=True)
        except Exception as exc:
            return {"ok": False, "error": f"GET login page failed: {exc}"}

        self._log(f"GET status: {get_resp.status_code}")
        self._log(f"Cookies after GET: {dict(self.session.cookies)}")

        hidden_fields = self._scrape_hidden_fields(get_resp.text)
        self._log(f"Scraped hidden fields: {list(hidden_fields.keys())}")

        if not hidden_fields:
            return {
                "ok": False,
                "error": "No hidden CSRF fields found on login page",
                "diag": f"GET {login_get_url} returned HTTP {get_resp.status_code}",
            }

        payload = {
            **hidden_fields,
            "ssoSession": "",
            "username": username,
            "password": password,
        }

        auth_url = f"{self.base_url}/tfk.msd/login/authenticate"
        self._log(f"POST {auth_url}")

        try:
            post_resp = self.session.post(
                auth_url,
                data=payload,
                timeout=(30, 60),
                allow_redirects=False,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": login_get_url,
                    "Origin": self.base_url,
                    "DNT": "1",
                },
            )
        except Exception as exc:
            return {"ok": False, "error": f"POST authenticate failed: {exc}"}

        status = post_resp.status_code
        location = post_resp.headers.get("Location", "")
        self._log(f"POST status: {status}, Location: {location!r}")

        if status not in {301, 302, 303, 307, 308}:
            return {
                "ok": False,
                "error": f"Login failed — server returned HTTP {status} (expected redirect)",
                "diag": "No redirect; likely wrong credentials or CSRF mismatch",
            }

        if "login/login" in location or "login/authenticate" in location:
            return {
                "ok": False,
                "error": "Login failed — server redirected back to login page",
                "diag": f"Redirect location: {location}",
            }

        # Follow the redirect to collect remaining cookies (MSD_Frontend, msdproxy)
        # and capture the proxy management base URL.
        # The redirect after login typically lands on /tfk.msd/dashboard/index (still port 80).
        # MSD_Frontend is only issued through a specific SSO handoff link in the dashboard
        # (not by directly hitting port 1920). We therefore:
        #   1. Fetch the dashboard to find the Schulfilter Plus link.
        #   2. Follow that link (which goes through port 80 SSO → port 1920).
        parsed_base = urlsplit(self.base_url)
        proxy_url_fallback = f"http://{parsed_base.hostname}:1920"

        # Step A: fetch the dashboard and look for a link to port 1920
        dashboard_url = location if location.startswith("http") else f"{self.base_url}{location}"
        self._log(f"GET dashboard: {dashboard_url}")
        sfp_link: str = ""
        try:
            dash_resp = self.session.get(dashboard_url, timeout=(30, 60), allow_redirects=True)
            self._log(f"Dashboard status: {dash_resp.status_code}, length: {len(dash_resp.text)}")
            # Look for any href that mentions port 1920 or schulfilter/sfp
            for pattern in [
                r'href=["\']([^"\']*1920[^"\']*)["\']',
                r'href=["\']([^"\']*schulfilter[^"\']*)["\']',
                r'href=["\']([^"\']*sfp[^"\']*)["\']',
                r'href=["\']([^"\']*proxy[^"\']*)["\']',
            ]:
                m = re.search(pattern, dash_resp.text, re.IGNORECASE)
                if m:
                    sfp_link = m.group(1)
                    self._log(f"Found Schulfilter Plus link: {sfp_link}")
                    break
            if not sfp_link:
                self._log("No Schulfilter Plus link found in dashboard HTML")
                self._log(f"Dashboard snippet: {dash_resp.text[:500]!r}")
        except Exception as exc:
            self._log(f"Dashboard fetch failed: {exc}")

        # Step B: follow the exact browser SSO bridge:
        #   myiframe -> iframe src /redirect.php?sID=... -> 302 to :1920/dsh...sid...
        # HTML-unescape the link first — dashboard HTML encodes &amp; as &amp;amp; etc.
        probe_url = html_unescape(sfp_link) if sfp_link else proxy_url_fallback
        if not probe_url.startswith("http"):
            probe_url = f"{self.base_url.rstrip('/')}/{probe_url.lstrip('/')}"

        # Preserve installation/product context from dashboard handoff URL.
        try:
            q = parse_qs(urlsplit(probe_url).query)
            self.proxy_installation = (q.get("installation", [""])[0] or "").strip()
            self.proxy_product_string = (q.get("product_string", ["sfp"])[0] or "sfp").strip()
            if self.proxy_installation:
                self._log(
                    "Proxy context: "
                    f"product={self.proxy_product_string}, installation={self.proxy_installation}"
                )
        except Exception:
            self.proxy_installation = ""
            self.proxy_product_string = "sfp"

        self._log(f"Probing Schulfilter Plus proxy at: {probe_url}")
        try:
            proxy_resp = self.session.get(
                probe_url,
                timeout=(30, 60),
                allow_redirects=True,
                headers={
                    "Referer": dashboard_url,
                    "DNT": "1",
                    "Upgrade-Insecure-Requests": "1",
                },
            )
            self.proxy_probe_url = probe_url
            self._log(f"Proxy probe response ({len(proxy_resp.text)} bytes): {proxy_resp.text[:300]!r}")

            redirect_rel = ""
            m_redirect = re.search(
                r'<iframe[^>]+src=["\']([^"\']*redirect\.php[^"\']*)["\']',
                proxy_resp.text,
                re.IGNORECASE,
            )
            if m_redirect:
                redirect_rel = html_unescape(m_redirect.group(1)).strip()

            if redirect_rel:
                redirect_url = redirect_rel
                if not redirect_url.startswith("http"):
                    redirect_url = f"{self.base_url.rstrip('/')}/{redirect_url.lstrip('/')}"
                self._log(f"GET redirect bridge: {redirect_url}")
                redirect_resp = self.session.get(
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
                self._log(f"redirect.php status: {redirect_resp.status_code}, Location: {location_1920!r}")

                if location_1920:
                    if not location_1920.startswith("http"):
                        location_1920 = f"http://{urlsplit(self.base_url).hostname}:1920/{location_1920.lstrip('/')}"
                    self.proxy_handoff_url = location_1920
                    handoff_resp = self.session.get(
                        location_1920,
                        timeout=(30, 60),
                        allow_redirects=True,
                        headers={
                            "Referer": f"{self.base_url}/",
                            "DNT": "1",
                            "Upgrade-Insecure-Requests": "1",
                        },
                    )
                    parsed_handoff = urlsplit(handoff_resp.url)
                    self.proxy_base_url = f"{parsed_handoff.scheme}://{parsed_handoff.netloc}"
                    self._log(f"Port-1920 handoff URL: {handoff_resp.url}")
                    self._log(f"Cookies after handoff: {dict(self.session.cookies)}")

            if not self.proxy_base_url:
                self._log("No redirect.php bridge found — falling back to direct port-1920 probe")
                self.proxy_base_url = proxy_url_fallback
                try:
                    cookie_header = self._build_proxy_cookie_header()
                    handoff_resp = self.session.get(
                        f"{self.proxy_base_url.rstrip('/')}/",
                        timeout=(30, 60),
                        allow_redirects=True,
                        headers={
                            "Referer": probe_url,
                            "DNT": "1",
                            "Upgrade-Insecure-Requests": "1",
                            **({"Cookie": cookie_header} if cookie_header else {}),
                        },
                    )
                    self.proxy_handoff_url = handoff_resp.url
                    self._log(f"Port-1920 fallback handoff URL: {handoff_resp.url}")
                    self._log(f"Cookies after handoff: {dict(self.session.cookies)}")
                except Exception as exc:
                    self._log(f"Port-1920 handoff failed ({exc}), keeping {self.proxy_base_url}")

            self._log(f"All cookies: {dict(self.session.cookies)}")
            self._log(f"Proxy management URL: {self.proxy_base_url}")
        except Exception as exc:
            self.proxy_base_url = proxy_url_fallback
            self.proxy_probe_url = proxy_url_fallback
            self._log(f"Proxy probe failed ({exc}), using {proxy_url_fallback}")

        return {"ok": True, "message": f"Login successful to {self.base_url}"}

    def _parse_log_table(self, html: str) -> list:
        """
        Parse the Schulfilter Plus log table from the HTML page.

        Extracts rows from <table id="table_sfpLogs"> and returns a list of dicts
        with keys: action, user, ip, time, url, category.
        """
        entries = []

        # Find the tbody inside the logs table specifically
        table_match = re.search(
            r'<table[^>]*id=["\']table_sfpLogs["\'][^>]*>(.*?)</table>',
            html,
            re.DOTALL | re.IGNORECASE,
        )
        if not table_match:
            self._log("table_sfpLogs not found in HTML")
            return entries

        tbody_match = re.search(r'<tbody>(.*?)</tbody>', table_match.group(1), re.DOTALL | re.IGNORECASE)
        if not tbody_match:
            self._log("No tbody found in logs table")
            return entries

        tbody = tbody_match.group(1)
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', tbody, re.DOTALL | re.IGNORECASE)

        for row in rows:
            # Extract cell text content, stripping any inner tags
            cells_raw = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
            cells = [html_unescape(re.sub(r'<[^>]+>', '', c)).strip() for c in cells_raw]
            if len(cells) < 6:
                continue
            entries.append({
                "action": cells[0],
                "user": cells[1],
                "ip": cells[2],
                "time": cells[3],
                "url": cells[4],
                "category": "" if cells[5] == "-" else cells[5],
            })

        return entries

    def fetch_logs(self, page_size: int = 300) -> dict:
        """
        Fetch the Schulfilter Plus filter log page and parse it.

        First fetches with the default page to confirm access, then sends a POST
        to request a larger page size so more entries are returned in one call.
        """
        if not self.proxy_base_url:
            return {"ok": False, "error": "Not authenticated — no proxy URL available"}

        # Use the exact browser flow observed on this appliance:
        #   GET /index.php (referer: dynamic :1920/dsh... handoff page)
        #   GET /index.php?action=logs
        base = self.proxy_base_url.rstrip("/")
        root_url = f"{base}/index.php"
        logs_url = f"{base}/index.php?action=logs"
        root_referer = self.proxy_handoff_url or f"{base}/"
        cookie_header = self._build_proxy_cookie_header()
        if cookie_header:
            self._log(f"Proxy Cookie header: {cookie_header}")

        # Preflight the index page first.
        try:
            root_resp = self.session.get(
                root_url,
                timeout=(30, 90),
                allow_redirects=True,
                headers={
                    "Referer": root_referer,
                    "DNT": "1",
                    "Upgrade-Insecure-Requests": "1",
                    **({"Cookie": cookie_header} if cookie_header else {}),
                },
            )
            self._log(f"GET entry status: {root_resp.status_code}, length: {len(root_resp.text)}, url: {root_url}")
        except Exception as exc:
            self._log(f"GET entry failed for {root_url} ({exc})")

        self._log(f"Logs URL: {logs_url}")
        try:
            get_resp = self.session.get(
                logs_url,
                timeout=(30, 90),
                allow_redirects=True,
                headers={
                    "Referer": root_url,
                    "DNT": "1",
                    "Upgrade-Insecure-Requests": "1",
                    **({"Cookie": cookie_header} if cookie_header else {}),
                },
            )
        except Exception as exc:
            return {"ok": False, "error": f"Failed to fetch logs: {exc}"}

        active_logs_url = logs_url
        self._log(f"GET logs status: {get_resp.status_code}, length: {len(get_resp.text)}")

        if "Fehlercode: 2.f" in get_resp.text:
            self._log("Access denied 2.f on logs GET; retrying after proxy handoff refresh")
            try:
                if self.proxy_probe_url:
                    self.session.get(
                        root_url,
                        timeout=(30, 90),
                        allow_redirects=True,
                        headers={
                            "Referer": self.proxy_probe_url,
                            "DNT": "1",
                            "Upgrade-Insecure-Requests": "1",
                            **({"Cookie": cookie_header} if cookie_header else {}),
                        },
                    )

                cookie_header = self._build_proxy_cookie_header()
                if cookie_header:
                    self._log(f"Proxy Cookie header (retry): {cookie_header}")

                get_resp = self.session.get(
                    logs_url,
                    timeout=(30, 90),
                    allow_redirects=True,
                    headers={
                        "Referer": root_url,
                        "DNT": "1",
                        "Upgrade-Insecure-Requests": "1",
                        **({"Cookie": cookie_header} if cookie_header else {}),
                    },
                )
                self._log(
                    f"GET logs retry status: {get_resp.status_code}, length: {len(get_resp.text)}"
                )
                active_logs_url = logs_url
            except Exception as exc:
                self._log(f"Retry after 2.f failed ({exc})")

        # Check whether we got redirected away from the logs page (e.g. back to login)
        if get_resp.status_code == 200 and "table_sfpLogs" not in get_resp.text:
            self._log(f"table_sfpLogs not found after GET — body: {get_resp.text[:300]!r}")

        # Step 2: POST to request a larger page size
        self._log(f"POST {active_logs_url} (page_size={page_size})")
        hidden_fields = self._scrape_hidden_fields(get_resp.text)
        payload = {
            key: value
            for key, value in hidden_fields.items()
            if key.startswith("sfpLogs[")
        }
        payload["sfpLogs[formPageSizeTop]"] = str(page_size)
        payload["sfpLogs[submitPageSizeTop]"] = "set_page_size"
        payload.setdefault("sfpLogs[formPageSizeOld]", "25")
        payload.setdefault("sfpLogs[formPageOld]", "1")
        payload.setdefault("sfpLogs[formFilterOld_freitext]", "")
        self._log(f"POST payload keys: {sorted(payload.keys())}")
        try:
            post_resp = self.session.post(
                active_logs_url,
                data=payload,
                timeout=(30, 90),
                allow_redirects=True,
                headers={
                    "Referer": active_logs_url,
                    "Origin": f"{urlsplit(active_logs_url).scheme}://{urlsplit(active_logs_url).netloc}",
                    "DNT": "1",
                    "Upgrade-Insecure-Requests": "1",
                    **({"Cookie": cookie_header} if cookie_header else {}),
                },
            )
        except Exception as exc:
            # Fall back to the GET response
            self._log(f"POST for page_size failed ({exc}), using GET result")
            entries = self._parse_log_table(get_resp.text)
            self._log(f"Parsed {len(entries)} log entries (from GET fallback)")
            return {"ok": True, "entries": entries}

        self._log(f"POST logs status: {post_resp.status_code}, length: {len(post_resp.text)}")

        # Use the POST response if it contains the table; fall back to GET otherwise
        html = post_resp.text if "table_sfpLogs" in post_resp.text else get_resp.text
        entries = self._parse_log_table(html)
        self._log(f"Parsed {len(entries)} log entries")

        return {"ok": True, "entries": entries}

    def _normalize_list_type(self, list_type: str) -> str:
        value = (list_type or "").strip().lower()
        if value in {"wl", "whitelist"}:
            return "wl"
        if value in {"bl", "blacklist"}:
            return "bl"
        return ""

    def _address_anchor(self, list_type: str) -> str:
        return "whitelist" if list_type == "wl" else "blacklist"

    def _address_delete_set_option(self, list_type: str) -> str:
        return "whitelist_entries" if list_type == "wl" else "blacklist_entries"

    def _request_address_lists_page(self) -> requests.Response:
        base = self.proxy_base_url.rstrip("/")
        url_candidates = [
            f"{base}/?action=address_lists",
            f"{base}/index.php?action=address_lists",
        ]
        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/index.php",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }

        last_err = None
        for url in url_candidates:
            try:
                resp = self.session.get(url, timeout=(30, 90), allow_redirects=True, headers=headers)
                self._log(f"GET address_lists: {url} -> {resp.status_code} ({len(resp.text)} bytes)")
                if resp.status_code == 200 and "action=address_lists" in resp.text and "table_wl_table" in resp.text:
                    return resp
                if resp.status_code == 200 and "table_bl_table" in resp.text:
                    return resp
                last_err = f"Address lists page missing expected markers at {url}"
            except Exception as exc:
                last_err = str(exc)
                self._log(f"Address list page request failed for {url}: {exc}")

        raise RuntimeError(last_err or "Failed to load address lists page")

    def _parse_address_table(self, html: str, table_id: str, row_class: str) -> list[dict]:
        entries: list[dict] = []
        table_match = re.search(
            rf'<table[^>]*id=["\']{re.escape(table_id)}["\'][^>]*>(.*?)</table>',
            html,
            re.DOTALL | re.IGNORECASE,
        )
        if not table_match:
            return entries

        tbody_match = re.search(r"<tbody>(.*?)</tbody>", table_match.group(1), re.DOTALL | re.IGNORECASE)
        if not tbody_match:
            return entries

        rows = re.findall(r"<tr[^>]*>(.*?)</tr>", tbody_match.group(1), re.DOTALL | re.IGNORECASE)
        for row in rows:
            id_match = re.search(
                rf'class=["\'][^"\']*{re.escape(row_class)}[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
                row,
                re.IGNORECASE,
            )
            if not id_match:
                id_match = re.search(
                    rf'value=["\']([^"\']+)["\'][^>]*class=["\'][^"\']*{re.escape(row_class)}[^"\']*["\']',
                    row,
                    re.IGNORECASE,
                )
            name_match = re.search(
                r'<td[^>]*class=["\'][^"\']*col_name[^"\']*["\'][^>]*>(.*?)</td>',
                row,
                re.DOTALL | re.IGNORECASE,
            )
            if not id_match or not name_match:
                continue

            entry_id = html_unescape(id_match.group(1)).strip()
            name_raw = re.sub(r"<[^>]+>", "", name_match.group(1))
            name = html_unescape(name_raw).strip()
            if not entry_id:
                continue
            entries.append({"id": entry_id, "name": name})

        return entries

    def _parse_total_count(self, html: str, list_type: str) -> int | None:
        anchor = self._address_anchor(list_type)
        block_match = re.search(
            rf'<div[^>]*id=["\']{re.escape(anchor)}["\'][^>]*>(.*?)</div>\s*<!-- CLOSER innerTemplateWrapper2 -->',
            html,
            re.DOTALL | re.IGNORECASE,
        )
        block = block_match.group(1) if block_match else html
        info_match = re.search(r'<span[^>]*class=["\']PaginationInfo["\'][^>]*>(.*?)</span>', block, re.DOTALL | re.IGNORECASE)
        if not info_match:
            return None
        text = html_unescape(re.sub(r"<[^>]+>", "", info_match.group(1))).strip()
        m = re.search(r"(\d+)", text)
        if not m:
            return None
        try:
            return int(m.group(1))
        except Exception:
            return None

    def fetch_address_lists(self) -> dict:
        if not self.proxy_base_url:
            return {"ok": False, "error": "Not authenticated — no proxy URL available"}

        try:
            page = self._request_address_lists_page()
        except Exception as exc:
            return {"ok": False, "error": f"Failed to load address lists page: {exc}"}

        html = page.text
        whitelist_entries = self._parse_address_table(html, "table_wl_table", "selectRow_whitelist")
        blacklist_entries = self._parse_address_table(html, "table_bl_table", "selectRow_blacklist")

        return {
            "ok": True,
            "whitelistEntries": whitelist_entries,
            "blacklistEntries": blacklist_entries,
            "whitelistTotal": self._parse_total_count(html, "wl") or len(whitelist_entries),
            "blacklistTotal": self._parse_total_count(html, "bl") or len(blacklist_entries),
        }

    def _ajax_check_url(self, candidate: str) -> str:
        base = self.proxy_base_url.rstrip("/")
        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/?action=address_lists",
            "X-Requested-With": "XMLHttpRequest",
            "DNT": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }
        resp = self.session.get(
            f"{base}/ajax.php",
            params={
                "action": "address_lists",
                "setOption": "ajaxCheckUrl",
                "filter": candidate,
            },
            timeout=(30, 60),
            allow_redirects=True,
            headers=headers,
        )
        return (resp.text or "").strip()

    def _ajax_check_set_list_entry(self, candidate: str) -> str:
        base = self.proxy_base_url.rstrip("/")
        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/?action=address_lists",
            "X-Requested-With": "XMLHttpRequest",
            "DNT": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }
        resp = self.session.get(
            f"{base}/ajax.php",
            params={
                "action": "address_lists",
                "setOption": "ajaxCheckSetListEntry",
                "name": candidate,
            },
            timeout=(30, 60),
            allow_redirects=True,
            headers=headers,
        )
        return (resp.text or "").strip()

    def _parse_ajax_success(self, payload: str) -> tuple[bool, str | None]:
        text = (payload or "").strip()
        if not text:
            return False, None
        first, _, rest = text.partition("|")
        return first.strip() == "1", rest.strip() or None

    def add_address_list_entry(self, list_type: str, entry_name: str) -> dict:
        normalized = self._normalize_list_type(list_type)
        value = (entry_name or "").strip()
        if normalized not in {"wl", "bl"}:
            return {"ok": False, "error": f"Unsupported list type: {list_type!r}"}
        if not value:
            return {"ok": False, "error": "Entry value is empty"}

        base = self.proxy_base_url.rstrip("/")
        anchor = self._address_anchor(normalized)
        set_option = "new_whitelist_list_entry" if normalized == "wl" else "new_blacklist_list_entry"
        form_action = f"{base}/?action=address_lists&dialog_subanker=#{anchor}"
        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/?action=address_lists",
            "Origin": f"{urlsplit(base).scheme}://{urlsplit(base).netloc}",
            "DNT": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }

        warnings: list[str] = []
        try:
            check_result = self._ajax_check_url(value)
            if check_result == "0v":
                warnings.append("Address appears unreachable (accepted after confirmation policy).")
            elif check_result not in {"1", "0v"}:
                return {"ok": False, "error": "Address validation failed", "diag": check_result}
        except Exception as exc:
            self._log(f"ajaxCheckUrl failed, proceeding with form submit: {exc}")

        resp = self.session.post(
            form_action,
            data={
                "setOption": set_option,
                "error_message": "",
                "new_filter": value,
            },
            timeout=(30, 90),
            allow_redirects=True,
            headers=headers,
        )

        if resp.status_code >= 400:
            return {"ok": False, "error": f"Create request failed with HTTP {resp.status_code}"}

        return {
            "ok": True,
            "message": f"Added entry to {anchor}",
            "warnings": warnings,
        }

    def edit_address_list_entry(
        self,
        list_type: str,
        entry_id: str,
        new_name: str,
        current_name: str = "",
    ) -> dict:
        normalized = self._normalize_list_type(list_type)
        entry_id = (entry_id or "").strip()
        new_name = (new_name or "").strip()
        current_name = (current_name or "").strip()
        if normalized not in {"wl", "bl"}:
            return {"ok": False, "error": f"Unsupported list type: {list_type!r}"}
        if not entry_id:
            return {"ok": False, "error": "Entry id is required"}
        if not new_name:
            return {"ok": False, "error": "Entry name is empty"}

        if current_name and current_name != new_name:
            check = self._ajax_check_set_list_entry(new_name)
            if check == "1":
                return {"ok": False, "error": "Entry already exists"}

        base = self.proxy_base_url.rstrip("/")
        anchor = self._address_anchor(normalized)
        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/?action=address_lists",
            "Origin": f"{urlsplit(base).scheme}://{urlsplit(base).netloc}",
            "DNT": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }

        resp = self.session.post(
            f"{base}/?action=address_lists&box_id=#{anchor}",
            data={
                "setOption": "setListEntry",
                "id": entry_id,
                "type": normalized,
                "lbid": "",
                "name": new_name,
            },
            timeout=(30, 90),
            allow_redirects=True,
            headers=headers,
        )

        if resp.status_code >= 400:
            return {"ok": False, "error": f"Edit request failed with HTTP {resp.status_code}"}

        return {"ok": True, "message": f"Updated entry {entry_id} in {anchor}"}

    def delete_address_list_entries(self, list_type: str, ids: list[str]) -> dict:
        normalized = self._normalize_list_type(list_type)
        if normalized not in {"wl", "bl"}:
            return {"ok": False, "error": f"Unsupported list type: {list_type!r}"}

        clean_ids = [str(value).strip() for value in ids if str(value).strip()]
        if not clean_ids:
            return {"ok": False, "error": "No entry ids provided for delete"}

        base = self.proxy_base_url.rstrip("/")
        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/?action=address_lists",
            "Origin": f"{urlsplit(base).scheme}://{urlsplit(base).netloc}",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded",
            "DNT": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }

        resp = self.session.post(
            f"{base}/ajax.php",
            data={
                "action": "deleteObjectList",
                "setOption": self._address_delete_set_option(normalized),
                "list": ",".join(clean_ids),
                "oid": "",
            },
            timeout=(30, 90),
            allow_redirects=True,
            headers=headers,
        )
        response_text = (resp.text or "").strip()
        ok, meta = self._parse_ajax_success(response_text)
        if not ok:
            return {
                "ok": False,
                "error": "Delete request was rejected",
                "diag": response_text,
            }

        return {
            "ok": True,
            "message": f"Deleted {len(clean_ids)} entries from {self._address_anchor(normalized)}",
            "meta": meta,
        }

    def import_address_list_entries(self, list_type: str, text_payload: str) -> dict:
        normalized = self._normalize_list_type(list_type)
        if normalized not in {"wl", "bl"}:
            return {"ok": False, "error": f"Unsupported list type: {list_type!r}"}

        import_text = (text_payload or "").strip("\r\n")
        if not import_text.strip():
            return {"ok": False, "error": "Import text is empty"}

        base = self.proxy_base_url.rstrip("/")
        anchor = self._address_anchor(normalized)
        set_option = "appendAddressList_wl" if normalized == "wl" else "appendAddressList_bl"
        text_field = "text_wl" if normalized == "wl" else "text_bl"

        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/?action=address_lists",
            "Origin": f"{urlsplit(base).scheme}://{urlsplit(base).netloc}",
            "DNT": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }

        resp = self.session.post(
            f"{base}/?action=address_lists#{anchor}",
            data={
                "setOption": set_option,
                text_field: import_text,
            },
            timeout=(30, 120),
            allow_redirects=True,
            headers=headers,
        )

        if resp.status_code >= 400:
            return {"ok": False, "error": f"Import request failed with HTTP {resp.status_code}"}

        imported_lines = len([line for line in import_text.splitlines() if line.strip()])
        return {
            "ok": True,
            "message": f"Submitted import for {imported_lines} entries to {anchor}",
            "importedLines": imported_lines,
        }

    def export_address_list_entries(self, list_type: str) -> dict:
        normalized = self._normalize_list_type(list_type)
        if normalized not in {"wl", "bl"}:
            return {"ok": False, "error": f"Unsupported list type: {list_type!r}"}

        base = self.proxy_base_url.rstrip("/")
        cookie_header = self._build_proxy_cookie_header()
        headers = {
            "Referer": f"{base}/?action=address_lists",
            "DNT": "1",
            **({"Cookie": cookie_header} if cookie_header else {}),
        }

        resp = self.session.get(
            f"{base}/ajax.php",
            params={
                "action": "exportAddressList",
                "setOption": normalized,
            },
            timeout=(30, 120),
            allow_redirects=True,
            headers=headers,
        )
        if resp.status_code >= 400:
            return {"ok": False, "error": f"Export request failed with HTTP {resp.status_code}"}

        filename = "whitelist_export.txt" if normalized == "wl" else "blacklist_export.txt"
        disposition = resp.headers.get("content-disposition", "")
        m = re.search(r'filename="?([^";]+)"?', disposition, re.IGNORECASE)
        if m:
            filename = m.group(1).strip()

        return {
            "ok": True,
            "exportContent": resp.text,
            "exportFilename": filename,
            "message": f"Exported {self._address_anchor(normalized)}",
        }

    def run_address_list_action(
        self,
        action: str,
        list_type: str,
        entry_id: str,
        entry_name: str,
        current_name: str,
        ids_raw: str,
        import_text: str,
    ) -> dict:
        normalized_action = (action or "").strip().lower()
        normalized_type = self._normalize_list_type(list_type)
        if normalized_type not in {"wl", "bl"}:
            return {"ok": False, "error": f"Unsupported list type: {list_type!r}"}

        if normalized_action == "add":
            return self.add_address_list_entry(normalized_type, entry_name)
        if normalized_action == "edit":
            return self.edit_address_list_entry(normalized_type, entry_id, entry_name, current_name)
        if normalized_action == "delete":
            ids = [part.strip() for part in (ids_raw or "").split(",") if part.strip()]
            return self.delete_address_list_entries(normalized_type, ids)
        if normalized_action == "import":
            return self.import_address_list_entries(normalized_type, import_text)
        if normalized_action == "export":
            return self.export_address_list_entries(normalized_type)

        return {"ok": False, "error": f"Unsupported address-list action: {action!r}"}


def main() -> None:
    mode = TFK_MODE

    if not MSD_USERNAME:
        print(json.dumps({"ok": False, "error": "MSD username not configured (TFK_MSD_USERNAME)"}))
        return
    if not MSD_PASSWORD:
        print(json.dumps({"ok": False, "error": "MSD password not configured (TFK_MSD_PASSWORD)"}))
        return
    if not BASE_URL:
        print(json.dumps({"ok": False, "error": "Base URL not configured (TFK_BASE_URL)"}))
        return

    msd_base = get_msd_base_url(BASE_URL)
    if not msd_base:
        print(json.dumps({"ok": False, "error": f"Could not derive MSD URL from base URL: {BASE_URL!r}"}))
        return

    session = MsdSession(msd_base, debug=DEBUG)

    if mode == "webfilter_test":
        result = session.authenticate(MSD_USERNAME, MSD_PASSWORD)
        print(json.dumps(result))

    elif mode == "webfilter_logs":
        auth_result = session.authenticate(MSD_USERNAME, MSD_PASSWORD)
        if not auth_result.get("ok"):
            print(json.dumps(auth_result))
            return
        logs_result = session.fetch_logs(page_size=300)
        print(json.dumps(logs_result))

    elif mode == "webfilter_address_lists":
        auth_result = session.authenticate(MSD_USERNAME, MSD_PASSWORD)
        if not auth_result.get("ok"):
            print(json.dumps(auth_result))
            return
        result = session.fetch_address_lists()
        print(json.dumps(result))

    elif mode == "webfilter_address_list_write":
        auth_result = session.authenticate(MSD_USERNAME, MSD_PASSWORD)
        if not auth_result.get("ok"):
            print(json.dumps(auth_result))
            return
        result = session.run_address_list_action(
            action=TFK_WF_ACTION,
            list_type=TFK_WF_LIST,
            entry_id=TFK_WF_ENTRY_ID,
            entry_name=TFK_WF_ENTRY_NAME,
            current_name=TFK_WF_CURRENT_NAME,
            ids_raw=TFK_WF_IDS,
            import_text=TFK_WF_IMPORT_TEXT,
        )
        print(json.dumps(result))

    else:
        print(json.dumps({"ok": False, "error": f"Unknown mode: {mode!r}"}))


if __name__ == "__main__":
    main()
