# TFK Manager (Tauri + React)

A desktop application for OPNsense lease operations and MSD webfilter operations, including static and dynamic DHCP workflows, firewall log streaming, and webfilter log/address-list management.

## License
- This project is licensed under PolyForm Noncommercial License 1.0.0.
- Commercial use, commercial modification, and use in commercial applications are not permitted without a separate commercial license from the author.
- See `LICENSE` for the full terms.

## Features
- Base URL-driven configuration (`login` and `dashboard` URLs are derived automatically, port `:81` enforced)
- **Static Gruen** lease workflow: CSV import/validation, diffing, add/update/delete review for the `lan` (Gruen) interface
- **Static WLANBYOD** lease workflow: identical workflow for the `opt4` (WLANBYOD) interface — separate panel, separate CSV state
- Dynamic lease workflow: load dynamic leases; move eligible leases to static and update conflicting static entries
  - Supported source interfaces for move/update: `Gruen` → `lan`, `WLANBYOD` → `opt4`
- Conflict helpers with suggested free IP/hostname and field-level update selection (IP/MAC)
- Lease views: `Static Gruen`, `Static WLANBYOD`, `Dynamic`, `Review`, and `Run Log`
- Collapsible review sections (Add, Conflicts, Deletes) per interface panel
- Static lease export fetches both Gruen (`export_static.csv`) and WLANBYOD (`export_static_wlanbyod.csv`) in a single API call
- Firewall stream view with live event ingestion and source health state
- Webfilter log view (MSD/Schulfilter Plus on port `80/1920`) with resilient polling and dynamic UI actions
- Webfilter address-list management for whitelist and blacklist entries:
	- Fetch lists and entry totals
	- Add, edit, and delete entries
	- Import and export list entries
- Source polling policy with per-source stale thresholds, retry backoff, and poll jitter helpers
- Settings persistence, run history, and in-app updater support

## Setup
1. Install Rust and Tauri prerequisites (Windows):
	- https://tauri.app/start/prerequisites/
2. Install dependencies:
	- npm install

## Backend (API Session)
1. Create a Python environment and install deps:
	- cd backend
	- python -m venv .venv
	- .venv\\Scripts\\activate
	- pip install -r requirements.txt

Only `requests` is required for backend dependencies. Playwright and selector configuration are no longer needed.

The backend authenticates against OPNsense, captures session cookies, and calls
the `/api/tfk/dhcp/*` endpoints directly.

## Server (Docker)

The repository now includes a containerized server API for server-first analysis endpoints:

- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `GET /api/history/events`
- `GET /api/history/trends`
- `GET /api/status/freshness`
- `POST /api/proxy/execute`
- `GET /api/proxy/operations/{requestId}`
- `GET /health`

### Files

- `server/Dockerfile` - server image build
- `docker-compose.yml` - local runtime stack
- `server/requirements.txt` - Python dependencies for the server container

### 1. User setup (`.env.server`)

Create a `.env.server` file in the repository root:

```env
TFK_SERVER_PORT=8080
TFK_SERVER_JWT_SECRET=replace-with-a-long-random-secret
TFK_SERVER_BOOTSTRAP_USERNAME=admin
TFK_SERVER_BOOTSTRAP_PASSWORD=replace-with-strong-password
TFK_SERVER_BOOTSTRAP_ROLE=admin
TFK_SERVER_CORS_ORIGINS=*
TFK_SERVER_COLLECTOR_ENABLED=1
TFK_SERVER_COLLECTOR_SAMPLE_MODE=0
TFK_SERVER_COLLECTOR_INTERVAL_SECONDS=20
TFK_SOURCE_OPNSENSE_BASE_URL=https://your-opnsense-host:81
TFK_SOURCE_API_USERNAME=replace-with-opnsense-api-username
TFK_SOURCE_API_KEY=replace-with-opnsense-api-key
TFK_SOURCE_API_SECRET=replace-with-opnsense-api-secret
TFK_SOURCE_OPNSENSE_USERNAME=replace-with-opnsense-username
TFK_SOURCE_OPNSENSE_PASSWORD=replace-with-opnsense-password
TFK_SOURCE_COOKIE_HEADER=
TFK_SOURCE_MSD_COOKIE=
TFK_SOURCE_VERIFY_TLS=0
TFK_SOURCE_CONNECT_TIMEOUT_SECONDS=10
TFK_SOURCE_READ_TIMEOUT_SECONDS=30
TFK_SOURCE_FIREWALL_MAX_EVENTS=25
TFK_SOURCE_DHCP_PATH=/api/tfk/dhcp/dynamic_leases
TFK_SOURCE_FIREWALL_STREAM_PATH=/api/diagnostics/firewall/streamLog
TFK_MSD_USERNAME=replace-with-msd-username
TFK_MSD_PASSWORD=replace-with-msd-password
TFK_PROXY_HMAC_SHARED_SECRET=replace-with-long-random-secret
TFK_PROXY_REQUEST_AUDIENCE=tfk-manager-server
TFK_PROXY_MAX_SKEW_SECONDS=120
TFK_PROXY_NONCE_TTL_SECONDS=300
TFK_SERVER_ALLOWED_PROXY_IPS=127.0.0.1/32
```

Notes:

- `TFK_SERVER_BOOTSTRAP_USERNAME` and `TFK_SERVER_BOOTSTRAP_PASSWORD` are used to create the initial login user if it does not exist yet.
- Supported roles from current authz policy are `admin` and `analyst`.
- If the bootstrap user already exists, startup will keep the existing account.
- `TFK_SERVER_COLLECTOR_ENABLED=1` runs a background collector loop in the API container.
- `TFK_SERVER_COLLECTOR_SAMPLE_MODE=0` enables real source ingestion using the `TFK_SOURCE_*` and `TFK_MSD_*` credentials.
- DHCP and firewall collectors now follow the same GUI-session flow as the desktop app: use `TFK_SOURCE_OPNSENSE_USERNAME` + `TFK_SOURCE_OPNSENSE_PASSWORD` (or import an existing browser cookie via `TFK_SOURCE_COOKIE_HEADER`) to access `/api/tfk/dhcp/*` and firewall stream endpoints.
- `TFK_SOURCE_DHCP_PATH` defaults to `/api/tfk/dhcp/dynamic_leases` and automatically falls back to `/api/tfk/dynamicleases/get`.
- Set `TFK_SERVER_COLLECTOR_SAMPLE_MODE=1` when you want demo data without source credentials.
- `TFK_PROXY_HMAC_SHARED_SECRET` must match the desktop delegated-mode secret (or `VITE_TFK_PROXY_HMAC_SHARED_SECRET`) for proxy request signing.
- `TFK_PROXY_REQUEST_AUDIENCE` must match the desktop audience configured in Settings.

### 2. Build and run the server

```powershell
docker compose --env-file .env.server up --build -d
```

### 3. Connection and health check

- Base URL: `http://localhost:8080`
- Health endpoint:

```powershell
curl http://localhost:8080/health
```

### 4. Login and endpoint usage

Get tokens:

```powershell
curl -X POST http://localhost:8080/api/auth/login \
	-H "Content-Type: application/json" \
	-d '{"username":"admin","password":"replace-with-strong-password"}'
```

Use the returned `accessToken` as bearer token:

```powershell
curl "http://localhost:8080/api/history/events?startAt=2026-03-21T00:00:00Z&endAt=2026-03-21T23:59:59Z&limit=100" \
	-H "Authorization: Bearer <accessToken>"
```

### 5. Stop the server

```powershell
docker compose down
```

Data persists in Docker volume `tfk_server_data` (SQLite DB at `/data/server.db` inside the container).

### 6. Reverse proxy hardening (required for internet-facing deployments)

For delegated operations over remote networks, place NGINX in front of the server and keep the API container private.

- Baseline hardened TLS profile and high-security mTLS profile:
	- `docs/server/reverse-proxy-hardening.md`
- Includes rate limiting, forwarded-header handling, request-size limits, method restrictions, and SSE-safe proxy timeout/buffering guidance.

Example delegated-mode call path:

1. Desktop logs in to server and receives JWT.
2. Desktop signs `POST /api/proxy/execute` with HMAC (`X-Proxy-Signature`).
3. Server validates nonce/timestamp/audience/signature and role/scope.
4. Server executes allow-listed operation and writes audit record.

### Backend modes used by the app
| Mode | Description |
|---|---|
| `export` | Fetch `/api/tfk/dhcp/static_leases` once; write `export_static.csv` (Gruen/`lan`) **and** `export_static_wlanbyod.csv` (WLANBYOD/`opt4`) |
| `dynamic` | Fetch dynamic leases from `/api/tfk/dhcp/leases` |
| `move_dynamic` | Move a dynamic lease to static — interface mapped via `TFK_IFACE` (`Gruen`→`lan`, `WLANBYOD`→`opt4`) |
| `update_dynamic_conflict` | Update an existing static lease from dynamic values — same interface mapping as above |

### Interface mapping
| UI name | OPNsense API `if` value |
|---|---|
| Gruen | `lan` |
| WLANBYOD | `opt4` |

## Run (Desktop)
- npm run tauri dev

## Build
Running `npm run build` automatically copies `backend/` into `src-tauri/resources/backend/` via `scripts/copy-backend.mjs` before compiling — no manual sync needed for production or CI builds.

## Tests
- Frontend/unit tests (Vitest):
	- `npm run test`
- Dynamic lease backend slice tests:
	- `python -m unittest -v backend/src/test_dynamic_leases_slice.py`

## Core architecture
- Frontend: `src/App.tsx` (single-file React app) with helper modules for parsing/protocol/polling logic.
- Tauri bridge: `src-tauri/src/lib.rs` commands invoke Python backend modes and return typed JSON payloads.
- Backend: `backend/src/opnsense_dhcp_ui.py`, `backend/src/fetch_firewall_log_stream.py`, and `backend/src/fetch_webfilter.py`.

## Security notes
- Passwords are stored in OS keyring via Tauri commands; avoid committing local capture artifacts or endpoint dumps.
- Keep OPNsense (`:81`) and MSD webfilter (`:80`/`:1920`) flows separated in implementation and diagnostics.

## Releases
Compiled binaries are available on the GitHub releases page:
- https://github.com/Borega/tfk-manager/releases

## Updates
- The app checks GitHub releases on startup and prompts to install when a new version is available.
- Update packages are signed; configure signing secrets for the release workflow:
	- `TAURI_SIGNING_PRIVATE_KEY`
	- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- The updater expects `latest.json` in the GitHub release assets.

## Notes
- CSV format expects semicolon separators.
- Backend script path is resolved automatically from the app; keep the `backend` folder next to the app.
- Configure `Python path` in Settings if you use a non-default Python install.
- `loginUrl` and `dashboardUrl` are read-only in the UI and derived from the Base URL.

## Commercial licensing
- If you need commercial use rights, request a separate commercial license from the project owner.
