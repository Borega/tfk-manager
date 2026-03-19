## Phase 4 Complete: Make Headers Clickable with Indicators

Transformed all analysis table headers into interactive sortable controls with visual direction indicators. Added getSortIndicator helper, CSS styling for hover effects, and onClick handlers to 31 column headers across three tables.

**Files created/changed:**
- src/tableSorting.ts
- src/tableSorting.test.ts
- src/App.tsx
- src/App.css

**Functions created/changed:**
- `getSortIndicator(sortConfig, columnName)` - Returns arrow indicators (↑/↓) for active sort

**Tests created/changed:**
- getSortIndicator returns empty string when sortConfig is null
- getSortIndicator returns empty string for inactive columns
- getSortIndicator returns " ↑" for ascending sort
- getSortIndicator returns " ↓" for descending sort

**Headers Made Interactive:**
- Top Risky Devices: 10 sortable columns
- All Correlated Devices: 12 sortable columns
- Unknown Private IPs: 3 sortable columns

**CSS Added:**
- `.fw-table th.sortable` with pointer cursor and no text selection
- `.fw-table th.sortable:hover` with background highlight
- `.sort-indicator` styling for arrow symbols

**Review Status:** APPROVED (after fixing tableId and column property name bugs)

**Git Commit Message:**
```
feat: Add interactive sortable headers to analysis tables

- Implement getSortIndicator for visual sort feedback
- Add onClick handlers to 31 column headers
- Add CSS styling for sortable headers with hover
- Fix tableId matching (allDevices, unknownIps)
- Fix Unknown IPs column keys (pass, block)
- 4 new tests for sort indicator logic
```
