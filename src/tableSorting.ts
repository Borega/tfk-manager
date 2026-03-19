/**
 * Table Sorting Utilities
 * 
 * Pure functions for sorting table data with support for:
 * - IPv4 address ordering
 * - Generic column sorting with direction
 * - Nullable value handling
 */

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
