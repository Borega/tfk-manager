# DHCP Lease Manager (Tauri + React)

A desktop UI for managing OPNsense static and dynamic DHCP leases with validation, conflict checks, and guided apply flows.

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
- Dynamic lease backend slice tests:
	- `python -m unittest -v backend/src/test_dynamic_leases_slice.py`

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
