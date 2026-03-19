## Phase 1 Complete: Build Sorting Utilities

Created pure, type-safe sorting utility functions with comprehensive test coverage. All 26 new tests passing, supporting IPv4 numeric comparison, generic column sorting, and nullable value handling for upcoming interactive table headers.

**Files created/changed:**
- src/tableSorting.ts
- src/tableSorting.test.ts

**Functions created/changed:**
- `ipToNumber(ip: string): number` - Converts IPv4 to 32-bit integer for numeric sort
- `compareNullable(a, b, nullsLast)` - Handles null/undefined value placement
- `compareByColumn<T>(a, b, key, direction)` - Generic type-safe column comparator

**Tests created/changed:**
- ipToNumber with valid IPv4 addresses (numeric ordering)
- ipToNumber with invalid/malformed IPs (defensive handling)
- compareByColumn with strings (ascending/descending)
- compareByColumn with numbers (ascending/descending)
- compareNullable with all null combinations (nulls-first/nulls-last)
- Integration tests for realistic sorting scenarios

**Review Status:** APPROVED

**Git Commit Message:**
```
feat: Add core sorting utilities for table columns

- Implement ipToNumber for IPv4 numeric comparison
- Add generic compareByColumn with type safety
- Add compareNullable for null/undefined handling
- Comprehensive test suite with 26 passing tests
```
