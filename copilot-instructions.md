<!-- GSD:project-start source:PROJECT.md -->
## Project

**TFK Manager Analysis Backend**

TFK Manager is evolving from a desktop-only analysis model to a hybrid architecture with a dedicated Linux server backend for long-term analysis data. The existing desktop app will remain the operator UI for DHCP and related workflows, while a new authenticated server service continuously collects analysis-relevant telemetry and serves historical data to clients. The goal is lower client resource usage and meaningful long-horizon analysis.

**Core Value:** Provide reliable long-term network behavior visibility (trend-first analysis) without requiring the desktop app to stay open continuously.

### Constraints

- **Platform**: Linux server target for backend runtime, with Docker Compose as preferred deployment path — simplifies first rollout and operations.
- **Compatibility**: Existing desktop app workflows must continue functioning during migration — avoid breaking operator tooling.
- **Data Boundaries**: Keep OPNsense and MSD authentication/error handling semantics distinct — avoids cross-system regression.
- **Security**: Server API must require authenticated access (JWT-based) before delivering historical analysis data.
- **Retention**: Database strategy must support at least 1 year of stored analysis-relevant data.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- TypeScript 5.8 - Frontend app and helper modules in `src/`.
- Rust (edition 2021) - Tauri IPC bridge and desktop shell in `src-tauri/src/`.
- Python 3.11+ - Backend API/session logic in `backend/src/`.
- JavaScript (Node ESM) - Build/release scripts in `scripts/`.
- YAML - CI workflow in `.github/workflows/release.yml`.
## Runtime
- Node.js 20+ (explicit in CI and docs) for Vite, tests, and scripts.
- Tauri v2 runtime for desktop app packaging/execution.
- Python interpreter selected in app settings (`pythonPath`) for backend subprocesses.
- npm for frontend and build tooling (`package.json`).
- Cargo for Rust/Tauri (`src-tauri/Cargo.toml`).
- pip for Python backend dependencies (`backend/requirements.txt`).
## Frameworks And Core Tooling
- React 19 with Vite 7 (`src/App.tsx`, `vite.config.ts`).
- Tauri JS APIs/plugins (`@tauri-apps/api`, updater, dialog, process).
- Tauri v2 + `serde` for typed payloads in `src-tauri/src/lib.rs`.
- `keyring` crate for OS credential storage.
- `requests` for HTTP/API/session handling (`backend/requirements.txt`).
- Standard library parsing/utilities (`csv`, `json`, `urllib`, `re`, `pathlib`).
- Vitest for TypeScript unit tests in `src/*.test.ts`.
- Python `unittest` in `backend/src/test_*.py`.
- Rust `#[cfg(test)]` unit tests in `src-tauri/src/lib.rs`.
## Key Dependencies
- `@tauri-apps/api` / Tauri plugins - Host bridge and desktop capabilities.
- `react` + `react-dom` - UI rendering and state-driven workflows.
- `tauri` crate - Native shell and IPC command registration.
- `requests` (Python) - OPNsense/MSD HTTP communication.
- `keyring` (Rust) - Persistent secure password storage.
## Configuration
- `tsconfig.json`, `tsconfig.node.json` - TypeScript settings.
- `vite.config.ts` - Dev server and Tauri-specific Vite behavior.
- `src-tauri/tauri.conf.json` - Tauri build, bundle, updater config.
- `src-tauri/Cargo.toml` - Rust crate config/dependencies.
- UI settings persisted via Tauri commands (`load_settings`, `save_settings`).
- Python subprocess behavior configured through `TFK_*` environment variables.
- Port split convention: OPNsense on `:81`, MSD webfilter on `:80`/`:1920`.
## Platform Requirements
- Windows-focused workflow, but CI builds on Windows/macOS/Linux.
- Rust toolchain + Node.js + Python required.
- Desktop binaries bundled via Tauri (`npm run tauri build`).
- Signed updater artifacts consumed from GitHub releases (`latest.json`).
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- Types and aliases use PascalCase (`SettingsState`, `RunPayload`).
- Variables/functions use camelCase (`normalizeBaseUrl`, `handleFetchWfLogs`).
- Constants use UPPER_SNAKE_CASE (`SOURCE_STALE_MS`, `MAX_FW_LOG_ENTRIES`).
- Utility modules commonly use camelCase filenames (`webfilterStatus.ts`, `topicSearch.ts`).
- Rust type/function names follow Rust idioms (snake_case functions, PascalCase structs).
- IPC payload structs use `#[serde(rename_all = "camelCase")]` to align with frontend payloads.
- Tauri commands are plain snake_case functions exposed via `#[tauri::command]`.
- Functions and module-level vars are snake_case.
- Data classes use PascalCase (`DhcpRow`, `DynamicLeaseRow`).
- Env vars are uniformly prefixed `TFK_`.
## Code Style
- Double quotes and semicolons are used consistently in source and tests.
- Small focused helper modules are preferred for reusable logic outside `App.tsx`.
- Standard rustfmt style in `src-tauri/src/lib.rs`.
- Early-return `Result<_, String>` patterns are common in command boundaries.
- Standard PEP-8 style with type hints in core paths.
- JSON-first stdout behavior for automation-friendly command wrapping.
## Import And Module Organization
- Grouped std imports first, then third-party crates (`tauri`, `serde`, `keyring`).
## Error Handling Patterns
- Rust command functions return `Result` with user-facing strings.
- Python scripts typically emit explicit JSON error payloads for machine parsing.
- Frontend maps backend status/error payloads into normalized UI status objects.
- Rust command wrappers scan stdout from the end and parse the last JSON line.
- This pattern appears in dynamic leases and webfilter command wrappers.
## Logging And Diagnostics
- Long-running tasks stream line-based logs via Tauri events (`run-log`).
- Firewall stream emits event-per-line (`firewall-log-entry`).
- Python debug behavior is controlled with `TFK_DEBUG`.
## Comments And Documentation
- Comments are generally used for non-obvious behaviors (subprocess policy, flow rationale, port boundaries).
- Project-level behavioral rules are documented in `.github/copilot-instructions.md`.
## Function And Module Design
- App-level orchestration remains centralized in `src/App.tsx`.
- Reusable and testable domain logic gets extracted into `src/*.ts` helper modules.
- Rust subprocess launch policy is centralized via `build_python_command` helpers.
- Backend script behavior is mode-driven using `TFK_MODE`.
## Domain-Specific Rules
- Port boundary separation is strict:
- CSV import/export format is semicolon-delimited and supports flexible name columns (`Name` / `Geraet`).
- Interface mapping convention: `Gruen -> lan`, `WLANBYOD -> opt4`.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- React UI issues typed IPC commands via Tauri.
- Rust layer owns OS integration, process spawning, and credential storage.
- Python scripts perform network-heavy OPNsense/MSD workflows.
- Long-running operations stream events back to UI.
## Layers
- Purpose: User workflows for DHCP, firewall stream, webfilter, and analysis.
- Contains: App state, table parsing/sorting/search helpers, invoke/event wiring.
- Location: `src/App.tsx` plus helper modules in `src/`.
- Depends on: Tauri invoke/events and local helper utilities.
- Purpose: Validate payloads, manage subprocesses, marshal JSON, persist settings/history.
- Contains: Tauri commands, process guards, keyring access, event emission.
- Location: `src-tauri/src/lib.rs`.
- Depends on: Tauri runtime, filesystem, Python executable path.
- Purpose: Execute API/session logic against OPNsense and MSD systems.
- Contains: Session/auth flows, CSV validation, endpoint calls, webfilter parsing.
- Location: `backend/src/opnsense_dhcp_ui.py`, `backend/src/fetch_webfilter.py`, `backend/src/fetch_firewall_log_stream.py`.
- Depends on: Network reachability and credential/cookie context provided by Rust layer.
## Data Flow
## Key Abstractions
- Rust structs with `#[serde(rename_all = "camelCase")]` mirror TS payload shapes.
- Python emits JSON consumed by Rust structs from stdout tail parsing.
- `build_python_command` and subprocess policy centralize launch behavior.
- `ProcessState` and `FirewallLogState` mutexes prevent orphaned child processes.
- Frontend source freshness/retry policy isolated in `src/sourcePollingPolicy.ts`.
- Webfilter overlap protection isolated in `src/webfilterInFlightGuard.ts`.
## Entry Points
- `src-tauri/src/main.rs` -> `tauri_app_lib::run()`.
- `src-tauri/src/lib.rs` `run()` with `generate_handler![...]` command list.
- `src/main.tsx` mounting `src/App.tsx`.
- Mode-driven execution in `backend/src/opnsense_dhcp_ui.py`.
- Specialized scripts in `backend/src/fetch_webfilter.py` and `backend/src/fetch_firewall_log_stream.py`.
## Error Handling And Cross-Cutting Concerns
- Rust returns `Result<..., String>` for all command boundaries.
- Python operations prefer machine-readable JSON errors on stdout.
- Credentials are isolated to OS keyring usage in Rust.
- Port-boundary rule (OPNsense `:81` vs MSD `:80`/`:1920`) is a core architectural constraint.
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
