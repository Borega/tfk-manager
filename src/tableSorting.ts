/**
 * Table Sorting Utilities
 * 
 * Pure functions for sorting table data with support for:
 * - IPv4 address ordering
 * - Generic column sorting with direction
 * - Nullable value handling
 * - Sort state toggling for UI interactions
 */

/**
 * Sort direction for ascending or descending order
 */
export type SortDirection = 'asc' | 'desc';

/**
 * Configuration object for active column sort.
 * null means no sort is active
 */
export type SortConfig = { column: string; direction: SortDirection } | null;

/**
 * Converts an IPv4 address string to a 32-bit unsigned integer
 * for numeric comparison.
 * 
 * @param ip - IPv4 address string (e.g., "192.168.1.1")
 * @returns 32-bit number or 0 if invalid
 * 
 * @example
 * ipToNumber("10.0.0.2") // 167772162
 * ipToNumber("192.168.1.1") // 3232235777
 */
export function ipToNumber(ip: string): number {
  if (!ip) {
    return 0;
  }

  const parts = ip.split(".");
  
  // Must have exactly 4 octets
  if (parts.length !== 4) {
    return 0;
  }

  // Parse and validate each octet
  const octets: number[] = [];
  for (const part of parts) {
    const num = parseInt(part, 10);
    
    // Check if valid integer and in range 0-255
    if (isNaN(num) || num < 0 || num > 255) {
      return 0;
    }
    
    octets.push(num);
  }

  // Convert to 32-bit integer using bit shifting
  // This ensures proper numeric ordering of IPs
  const result = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  
  // Convert to unsigned by applying >>> 0
  return result >>> 0;
}

/**
 * Compares two nullable string values, handling null/undefined placement.
 * 
 * @param a - First value (string | null | undefined)
 * @param b - Second value (string | null | undefined)
 * @param nullsLast - If true, nulls/undefined sort last; if false, first
 * @returns Standard comparator result: negative if a < b, 0 if equal, positive if a > b
 * 
 * @example
 * compareNullable("apple", "banana", true) // negative
 * compareNullable(null, "value", true) // 1 (null goes last)
 * compareNullable(null, undefined, true) // 0 (both treated equally)
 */
export function compareNullable(
  a: string | null | undefined,
  b: string | null | undefined,
  nullsLast: boolean
): number {
  const aIsNull = a == null;
  const bIsNull = b == null;

  // Both are null/undefined
  if (aIsNull && bIsNull) {
    return 0;
  }

  // Only a is null
  if (aIsNull) {
    return nullsLast ? 1 : -1;
  }

  // Only b is null
  if (bIsNull) {
    return nullsLast ? -1 : 1;
  }

  // Neither is null - standard string comparison
  return a!.localeCompare(b!);
}

/**
 * Generic comparator function for sorting table rows by a specific column.
 * 
 * @param a - First row object
 * @param b - Second row object
 * @param key - Column key to sort by
 * @param direction - Sort direction: 'asc' for ascending, 'desc' for descending
 * @returns Standard comparator result for use with Array.sort()
 * 
 * @example
 * const rows = [{ name: "Alice", age: 30 }, { name: "Bob", age: 25 }];
 * rows.sort((a, b) => compareByColumn(a, b, "age", "asc"));
 */
export function compareByColumn<T>(
  a: T,
  b: T,
  key: keyof T,
  direction: "asc" | "desc"
): number {
  const aVal = a[key];
  const bVal = b[key];

  let result = 0;

  // Handle different types
  if (typeof aVal === "number" && typeof bVal === "number") {
    result = aVal - bVal;
  } else if (typeof aVal === "string" && typeof bVal === "string") {
    result = aVal.localeCompare(bVal);
  } else {
    // Fallback for other types (try converting to string)
    const aStr = String(aVal ?? "");
    const bStr = String(bVal ?? "");
    result = aStr.localeCompare(bStr);
  }

  // Reverse result if descending
  return direction === "desc" ? -result : result;
}

/**
 * Toggles sort state when a column header is clicked.
 * Implements a two-state cycle (asc ↔ desc) for the same column,
 * and resets to asc when clicking a different column.
 * 
 * @param currentSort - Current sort configuration (null if no sort active)
 * @param clickedColumn - Column name that was clicked
 * @returns New sort configuration after the toggle
 * 
 * @example
 * toggleSort(null, "hostname") // { column: "hostname", direction: "asc" }
 * toggleSort({ column: "hostname", direction: "asc" }, "hostname") // { column: "hostname", direction: "desc" }
 * toggleSort({ column: "hostname", direction: "desc" }, "hostname") // { column: "hostname", direction: "asc" }
 * toggleSort({ column: "hostname", direction: "desc" }, "ip") // { column: "ip", direction: "asc" }
 */
export function toggleSort(
  currentSort: SortConfig,
  clickedColumn: string
): SortConfig {
  // No current sort or clicking a new column: start with asc
  if (currentSort === null || currentSort.column !== clickedColumn) {
    return { column: clickedColumn, direction: 'asc' };
  }

  // Same column: toggle direction (asc → desc, desc → asc)
  return {
    column: clickedColumn,
    direction: currentSort.direction === 'asc' ? 'desc' : 'asc'
  };
}

/**
 * Compares two IPv4 addresses numerically.
 * Uses ipToNumber() to convert IPs to 32-bit integers for proper numeric comparison.
 * 
 * @param a - First IPv4 address string
 * @param b - Second IPv4 address string
 * @returns Standard comparator result: negative if a < b, 0 if equal, positive if a > b
 * 
 * @example
 * compareIp("10.0.0.2", "10.0.0.10") // -8 (2 < 10 numerically)
 * compareIp("10.0.0.10", "192.168.1.1") // negative (smaller IP)
 */
export function compareIp(a: string, b: string): number {
  return ipToNumber(a) - ipToNumber(b);
}

/**
 * Compares two ISO 8601 timestamp strings numerically by converting to milliseconds.
 * Empty or invalid strings are treated as 0 and sort last.
 * 
 * @param a - First ISO timestamp string
 * @param b - Second ISO timestamp string
 * @param toTimeMillis - Function to convert ISO timestamp string to milliseconds
 * @returns Standard comparator result: negative if a < b, 0 if equal, positive if a > b
 * 
 * @example
 * const toTimeMillis = (s: string) => Date.parse(s);
 * compareTimestamp("2024-01-01T10:00:00Z", "2024-01-01T09:00:00Z", toTimeMillis) // > 0
 */
export function compareTimestamp(
  a: string,
  b: string,
  toTimeMillis: (value: string) => number
): number {
  return toTimeMillis(a) - toTimeMillis(b);
}

/**
 * Compares two boolean values.
 * True sorts before false (natural descending order for booleans).
 * 
 * @param a - First boolean value
 * @param b - Second boolean value
 * @returns -1 if a is true and b is false, 1 if a is false and b is true, 0 if equal
 * 
 * @example
 * compareBoolean(true, false) // -1 (true comes first)
 * compareBoolean(false, true) // 1 (false comes after)
 * compareBoolean(true, true) // 0
 */
export function compareBoolean(a: boolean, b: boolean): number {
  // For descending (natural order): true comes before false
  // a === b ? 0 : a ? -1 : 1
  // If a == b, return 0
  // If a is true (and b is false), return -1 (a comes first)
  // If a is false (and b is true), return 1 (a comes after)
  return a === b ? 0 : a ? -1 : 1;
}

/**
 * Business-order comparison for network segment types.
 * Order: Static Gruen → Static BYOD → Dynamic Gruen → Dynamic BYOD → Unknown
 * 
 * @param a - First segment name
 * @param b - Second segment name
 * @returns Standard comparator result based on business order
 * 
 * @example
 * compareSegment("Static Gruen", "Static BYOD") // -1 (Static Gruen comes first)
 * compareSegment("Dynamic BYOD", "Unknown") // -1
 * compareSegment("Unknown", "Static Gruen") // 1 (Unknown comes last)
 */
export function compareSegment(a: string, b: string): number {
  const SEGMENT_ORDER = [
    "Static Gruen",
    "Static BYOD",
    "Dynamic Gruen",
    "Dynamic BYOD",
    "Unknown",
  ];

  const aIndex = SEGMENT_ORDER.indexOf(a);
  const bIndex = SEGMENT_ORDER.indexOf(b);

  // If either segment is not recognized, treat as Unknown (last position)
  const aPos = aIndex >= 0 ? aIndex : SEGMENT_ORDER.length - 1;
  const bPos = bIndex >= 0 ? bIndex : SEGMENT_ORDER.length - 1;

  return aPos - bPos;
}

/**
 * Applies a sort configuration to an array of rows.
 * Returns a new sorted array without mutating the original.
 * Uses specialized comparators for specific columns (ip, lastSeen, hasDualBlock, segment).
 * 
 * @param rows - Array of row objects to sort
 * @param sortConfig - Sort configuration (column and direction), or null to preserve order
 * @param toTimeMillis - Optional function to convert timestamp strings to milliseconds (required for 'lastSeen' sorting)
 * @returns New sorted array if sortConfig is present, otherwise returns original array unchanged
 * 
 * @example
 * const rows = [{ name: "Bob", age: 25 }, { name: "Alice", age: 30 }];
 * applySortToRows(rows, { column: "name", direction: "asc" })
 * // Returns: [{ name: "Alice", age: 30 }, { name: "Bob", age: 25 }]
 * 
 * // With special comparators
 * const toTimeMillis = (s: string) => Date.parse(s);
 * applySortToRows(devices, { column: "ip", direction: "asc" }, toTimeMillis)
 * // Uses compareIp for numeric IP sorting
 */
export function applySortToRows<T>(
  rows: T[],
  sortConfig: SortConfig | null,
  toTimeMillis?: (value: string) => number
): T[] {
  // If no sort config, return rows unchanged (preserve default order)
  if (sortConfig === null) {
    return rows;
  }

  const column = sortConfig.column;
  const direction = sortConfig.direction;

  // Create a shallow copy to avoid mutating the original array
  return rows.slice().sort((a, b) => {
    let result = 0;

    // Use specialized comparators for specific columns
    if (column === "ip") {
      const aVal = (a as Record<string, unknown>)[column] as string;
      const bVal = (b as Record<string, unknown>)[column] as string;
      result = compareIp(aVal, bVal);
    } else if (column === "lastSeen") {
      const aVal = (a as Record<string, unknown>)[column] as string;
      const bVal = (b as Record<string, unknown>)[column] as string;
      if (toTimeMillis) {
        result = compareTimestamp(aVal, bVal, toTimeMillis);
      } else {
        // Fallback to default comparison if no toTimeMillis provided
        result = compareByColumn(a, b, column as keyof T, "asc");
      }
    } else if (column === "hasDualBlock") {
      const aVal = (a as Record<string, unknown>)[column] as boolean;
      const bVal = (b as Record<string, unknown>)[column] as boolean;
      result = compareBoolean(aVal, bVal);
    } else if (column === "segment") {
      const aVal = (a as Record<string, unknown>)[column] as string;
      const bVal = (b as Record<string, unknown>)[column] as string;
      result = compareSegment(aVal, bVal);
    } else {
      // Default behavior for all other columns
      result = compareByColumn(a, b, column as keyof T, "asc");
    }

    // Apply direction (reverse result if descending)
    return direction === "desc" ? -result : result;
  });
}

/**
 * Returns a visual sort indicator (arrow) for a column in the table header.
 * Used to show users which column is currently sorted and in which direction.
 * 
 * @param sortConfig - Current sort configuration (null if no sort active)
 * @param columnName - Name of the column to check
 * @returns "" if no sort or different column is active, " ↑" for ascending, " ↓" for descending
 * 
 * @example
 * getSortIndicator(null, "name") // ""
 * getSortIndicator({ column: "name", direction: "asc" }, "name") // " ↑"
 * getSortIndicator({ column: "name", direction: "desc" }, "name") // " ↓"
 * getSortIndicator({ column: "name", direction: "asc" }, "age") // "" (different column)
 */
export function getSortIndicator(
  sortConfig: SortConfig | null,
  columnName: string
): string {
  // No sort active
  if (sortConfig === null) {
    return "";
  }

  // Different column is sorted
  if (sortConfig.column !== columnName) {
    return "";
  }

  // Same column - return indicator based on direction
  return sortConfig.direction === 'asc' ? " ↑" : " ↓";
}
