## Plan: Sortable Analysis Table Columns

Add interactive sortable columns to all three Analysis tab tables (Top Risky Devices, All Correlated Devices, Unknown Private IPs). Users can click column headers to toggle between ascending and descending sort order, with special handling for IP addresses (numeric order), timestamps, booleans, and segments (business-defined order).

**Phases: 5**

1. **Phase 1: Build Sorting Utilities**
    - **Objective:** Create pure, test-first sorting helpers that can safely handle numbers, strings, nullable values, and IPv4 ordering.
    - **Files/Functions to Modify/Create:**
        - [src/tableSorting.ts](src/tableSorting.ts) (new)
        - [src/tableSorting.test.ts](src/tableSorting.test.ts) (new)
    - **Tests to Write:**
        - `ipToNumber` converts valid IPv4 to 32-bit integer for numeric comparison
        - `ipToNumber` handles malformed/invalid IPs defensively
        - `compareByColumn` sorts strings ascending and descending
        - `compareByColumn` sorts numbers ascending and descending
        - `compareNullable` places null/undefined last in both directions
    - **Steps:**
        1. Create failing test for `ipToNumber` with valid IPv4 addresses (10.0.0.2, 10.0.0.10, 192.168.1.1)
        2. Create failing test for `ipToNumber` edge cases (invalid IPs return NaN or fallback)
        3. Implement minimal `ipToNumber` to pass tests
        4. Create failing tests for `compareByColumn` with sample string and number data
        5. Implement minimal generic comparator
        6. Create failing tests for `compareNullable` with both/one/no nulls
        7. Implement nullable handler
        8. Run all tests and confirm they pass

2. **Phase 2: Add Analysis Sort State and Toggle Logic**
    - **Objective:** Add per-table sort state with two-state cycle (asc ↔ desc) triggered by header clicks.
    - **Files/Functions to Modify/Create:**
        - [src/App.tsx](src/App.tsx): Add state variables and toggle handler
        - [src/tableSorting.test.ts](src/tableSorting.test.ts): Add tests for toggle logic helper
    - **Tests to Write:**
        - `toggleSort` cycles null → asc → desc → asc (two-state)
        - `toggleSort` with different column resets to asc on new column
        - Sort state type safety (column keys match table types)
    - **Steps:**
        1. Create failing test for `toggleSort` helper function with two-state cycle
        2. Create failing test for column switching behavior
        3. Implement `toggleSort` pure helper in [src/tableSorting.ts](src/tableSorting.ts)
        4. Add three `useState<SortConfig | null>` variables in [src/App.tsx](src/App.tsx) for each table
        5. Add `handleSort(tableId, column)` handler that calls `toggleSort`
        6. Run tests and confirm toggle logic passes

3. **Phase 3: Apply Sorting to Derived Analysis Rows**
    - **Objective:** Apply selected sort configs to displayed arrays while preserving default risk-based ranking when no sort is active.
    - **Files/Functions to Modify/Create:**
        - [src/App.tsx](src/App.tsx): Add `useMemo` for sorted arrays
        - [src/tableSorting.ts](src/tableSorting.ts): Add `applySortToRows` function
        - [src/tableSorting.test.ts](src/tableSorting.test.ts): Add integration tests
    - **Tests to Write:**
        - `applySortToRows` returns original array when sortConfig is null
        - `applySortToRows` sorts by numeric column ascending/descending
        - `applySortToRows` sorts by string column ascending/descending
        - `applySortToRows` does not mutate original array
    - **Steps:**
        1. Create failing tests for `applySortToRows` with sample `AnalysisDeviceRow[]` data
        2. Create failing test for immutability (original array unchanged)
        3. Implement `applySortToRows` using column-specific comparators
        4. Add three `useMemo` hooks in [src/App.tsx](src/App.tsx) for sorted arrays
        5. Update table rendering to use sorted arrays instead of originals
        6. Run tests and verify sorting applies correctly

4. **Phase 4: Make Headers Clickable with Indicators**
    - **Objective:** Turn analysis table headers into sortable controls with visible direction indicators (↑/↓).
    - **Files/Functions to Modify/Create:**
        - [src/App.tsx](src/App.tsx): Modify header `<th>` elements
        - [src/App.css](src/App.css): Add sortable header styles
        - [src/tableSorting.ts](src/tableSorting.ts): Add `getSortIndicator` helper
        - [src/tableSorting.test.ts](src/tableSorting.test.ts): Add indicator tests
    - **Tests to Write:**
        - `getSortIndicator` returns "↑" for ascending, "↓" for descending, "" for unsorted
        - `getSortIndicator` correctly identifies active column
    - **Steps:**
        1. Create failing tests for `getSortIndicator` helper function
        2. Implement minimal `getSortIndicator` to pass tests
        3. Modify all column headers in three tables to include `onClick` handlers
        4. Add sort indicator rendering to each header
        5. Add CSS for `.sortable` class with cursor pointer and hover effect
        6. Run tests and manually verify headers are clickable with correct indicators

5. **Phase 5: Final Behavior Polish**
    - **Objective:** Ensure special-case sorting correctness (IP numeric, timestamp, booleans, segments) and refresh reset behavior.
    - **Files/Functions to Modify/Create:**
        - [src/tableSorting.ts](src/tableSorting.ts): Add specialized comparators
        - [src/tableSorting.test.ts](src/tableSorting.test.ts): Add special-case tests
        - [src/App.tsx](src/App.tsx): Wire special comparators and reset logic
    - **Tests to Write:**
        - `compareIp` sorts ["10.0.0.10", "10.0.0.2", "192.168.1.1"] numerically correct
        - `compareTimestamp` handles ISO strings and empty values (empty last)
        - `compareBoolean` sorts true before false in descending
        - `compareSegment` orders Static Gruen → Static BYOD → Dynamic Gruen → Dynamic BYOD → Unknown
        - Sort state resets when refresh button clicked
    - **Steps:**
        1. Create failing tests for IP numeric comparison with realistic examples
        2. Create failing tests for timestamp, boolean, and segment ordering
        3. Implement specialized comparator functions
        4. Wire comparators into `applySortToRows` based on column name
        5. Add sort state reset in `handleRefreshAnalysis` function
        6. Create failing test for refresh reset behavior
        7. Run full test suite and confirm all tests pass
        8. Manual verification: Click headers, verify sorting works correctly for all column types

**Decisions Made:**
- **Sort cycle:** Two-state (asc ↔ desc), no return to unsorted state
- **Null handling:** Missing values (hostname, user, mac) always sort last in both directions
- **Segment order:** Fixed business order (Static Gruen, Static BYOD, Dynamic Gruen, Dynamic BYOD, Unknown)
- **Refresh behavior:** Clicking "Refresh analysis sources" resets all sort states to default (null)
