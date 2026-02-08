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

## Backend (Playwright)
1. Create a Python environment and install deps:
	- cd backend
	- python -m venv .venv
	- .venv\\Scripts\\activate
	- pip install -r requirements.txt
2. Install Playwright browsers:
	- python -m playwright install

## Run (Desktop)
- npm run tauri dev

## Releases
Compiled binaries are available on the GitHub releases page:
- https://github.com/Borega/tfk-manager/releases

## Notes
- CSV format expects semicolon separators.
- Backend script path is resolved automatically from the app; keep the `backend` folder next to the app.
- Configure `Python path` in Settings if you use a non-default Python install.
