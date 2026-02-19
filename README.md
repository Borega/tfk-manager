# DHCP Lease Manager (Tauri + React)

A desktop UI for managing OPNsense static and dynamic DHCP leases with validation, conflict checks, and guided apply flows.

## License
- This project is licensed under PolyForm Noncommercial License 1.0.0.
- Commercial use, commercial modification, and use in commercial applications are not permitted without a separate commercial license from the author.
- See `LICENSE` for the full terms.

## Features
- Base URL-driven configuration (`login` and `dashboard` URLs are derived automatically, port `:81` enforced)
- Static lease workflow: CSV import/validation, diffing, add/update/delete review
- Dynamic lease workflow: load dynamic leases, move eligible leases to static, and update conflicting static entries
- Conflict helpers with suggested free IP/hostname and field-level update selection (IP/MAC)
- Lease views: `Static`, `Dynamic`, `Review`, and `Run Log`
- Collapsible review sections (Add, Conflicts, Deletes)
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
- `export`: export static leases to `export_static.csv`
- `dynamic`: fetch dynamic leases
- `move_dynamic`: move a dynamic lease to static (restricted to `Gruen` source interface)
- `update_dynamic_conflict`: update an existing static lease from dynamic values

## Run (Desktop)
- npm run tauri dev

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
