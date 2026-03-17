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
- Backend: `backend/src/opnsense_dhcp_ui.py` and `backend/src/fetch_firewall_log_stream.py`.

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
