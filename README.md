# TFK Manager (Tauri + React)

A desktop UI for validating, diffing, and applying OPNsense static DHCP CSV changes.

## Features
- Settings panel for update/skip behavior
- CSV import and validation (incoming + existing export)
- Diff summary (adds, conflicts, exact matches, duplicates)
- Confirmation gate before running changes
- Run log preview
- Settings persistence and run history

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

## Run (Desktop)
- npm run tauri dev

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
