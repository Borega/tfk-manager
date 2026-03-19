import { describe, expect, it } from "vitest";
import { compareByColumn, compareNullable, ipToNumber, toggleSort, type SortConfig } from "./tableSorting";

describe("ipToNumber", () => {
  it("converts valid IPv4 address 10.0.0.2 to 167772162", () => {
    expect(ipToNumber("10.0.0.2")).toBe(167772162);
  });

  it("converts valid IPv4 address 10.0.0.10 to 167772170", () => {
    expect(ipToNumber("10.0.0.10")).toBe(167772170);
  });

  it("converts valid IPv4 address 192.168.1.1 to 3232235777", () => {
    expect(ipToNumber("192.168.1.1")).toBe(3232235777);
  });

  it("returns 0 for empty string", () => {
    expect(ipToNumber("")).toBe(0);
  });

  it("returns 0 for malformed IP (too many octets)", () => {
    expect(ipToNumber("10.0.0.2.1")).toBe(0);
  });

  it("returns 0 for malformed IP (too few octets)", () => {
    expect(ipToNumber("10.0.0")).toBe(0);
  });

  it("returns 0 for malformed IP (non-numeric octets)", () => {
    expect(ipToNumber("10.a.0.2")).toBe(0);
  });

  it("returns 0 for malformed IP (octets out of range)", () => {
    expect(ipToNumber("10.256.0.2")).toBe(0);
  });
});

describe("compareNullable", () => {
  it("returns 0 when both values are null", () => {
    expect(compareNullable(null, null, true)).toBe(0);
  });

  it("returns 0 when both values are undefined", () => {
    expect(compareNullable(undefined, undefined, true)).toBe(0);
  });

  it("returns 1 (a goes last) when only a is null and nullsLast is true", () => {
    expect(compareNullable(null, "value", true)).toBe(1);
  });

  it("returns -1 (a goes first) when only a is null and nullsLast is false", () => {
    expect(compareNullable(null, "value", false)).toBe(-1);
  });

  it("returns -1 (b goes last) when only b is null and nullsLast is true", () => {
    expect(compareNullable("value", null, true)).toBe(-1);
  });

  it("returns 1 (b goes first) when only b is null and nullsLast is false", () => {
    expect(compareNullable("value", null, false)).toBe(1);
  });

  it("delegates to string comparison when neither is null (alphabetically)", () => {
    expect(compareNullable("apple", "banana", true)).toBeLessThan(0);
  });

  it("delegates to string comparison when neither is null (alphabetically reverse)", () => {
    expect(compareNullable("banana", "apple", true)).toBeGreaterThan(0);
  });

  it("returns 0 when both values are identical strings", () => {
    expect(compareNullable("same", "same", true)).toBe(0);
  });

  it("handles mix of null and undefined (null and undefined are treated the same)", () => {
    expect(compareNullable(null, undefined, true)).toBe(0);
  });
});

describe("compareByColumn", () => {
  interface TestRow {
    name: string;
    age: number;
    ip: string;
  }

  const rows: TestRow[] = [
    { name: "Alice", age: 30, ip: "10.0.0.5" },
    { name: "Bob", age: 25, ip: "10.0.0.2" },
    { name: "Charlie", age: 35, ip: "192.168.1.1" },
  ];

  describe("string column sorting", () => {
    it("sorts strings in ascending order", () => {
      expect(compareByColumn(rows[0], rows[1], "name", "asc")).toBeLessThan(0);
      expect(compareByColumn(rows[1], rows[0], "name", "asc")).toBeGreaterThan(0);
    });

    it("sorts strings in descending order", () => {
      expect(compareByColumn(rows[0], rows[1], "name", "desc")).toBeGreaterThan(0);
      expect(compareByColumn(rows[1], rows[0], "name", "desc")).toBeLessThan(0);
    });

    it("returns 0 for identical strings", () => {
      expect(compareByColumn(rows[0], rows[0], "name", "asc")).toBe(0);
    });
  });

  describe("number column sorting", () => {
    it("sorts numbers in ascending order", () => {
      expect(compareByColumn(rows[1], rows[0], "age", "asc")).toBeLessThan(0);
      expect(compareByColumn(rows[0], rows[1], "age", "asc")).toBeGreaterThan(0);
    });

    it("sorts numbers in descending order", () => {
      expect(compareByColumn(rows[1], rows[0], "age", "desc")).toBeGreaterThan(0);
      expect(compareByColumn(rows[0], rows[1], "age", "desc")).toBeLessThan(0);
    });

    it("returns 0 for identical numbers", () => {
      expect(compareByColumn(rows[0], rows[0], "age", "asc")).toBe(0);
    });
  });

  describe("complex sorting scenarios", () => {
    it("correctly sorts IP addresses as strings", () => {
      // "10.0.0.2" should come before "192.168.1.1" in string comparison
      const result = compareByColumn(rows[1], rows[2], "ip", "asc");
      expect(result).toBeLessThan(0);
    });

    it("handles array sort with compareByColumn", () => {
      const sorted = [...rows].sort((a, b) => compareByColumn(a, b, "age", "asc"));
      expect(sorted[0].age).toBe(25);
      expect(sorted[1].age).toBe(30);
      expect(sorted[2].age).toBe(35);
    });
  });
});

describe("toggleSort", () => {
  it("returns asc for a new column when currentSort is null", () => {
    const result = toggleSort(null, "hostname");
    expect(result).toEqual({ column: "hostname", direction: "asc" });
  });

  it("toggles from asc to desc for the same column", () => {
    const currentSort: SortConfig = { column: "hostname", direction: "asc" };
    const result = toggleSort(currentSort, "hostname");
    expect(result).toEqual({ column: "hostname", direction: "desc" });
  });

  it("toggles from desc to asc for the same column (two-state cycle)", () => {
    const currentSort: SortConfig = { column: "hostname", direction: "desc" };
    const result = toggleSort(currentSort, "hostname");
    expect(result).toEqual({ column: "hostname", direction: "asc" });
  });

  it("resets to asc when clicking a different column", () => {
    const currentSort: SortConfig = { column: "hostname", direction: "desc" };
    const result = toggleSort(currentSort, "ip");
    expect(result).toEqual({ column: "ip", direction: "asc" });
  });

  it("handles empty string column name", () => {
    const result = toggleSort(null, "");
    expect(result).toEqual({ column: "", direction: "asc" });
  });
});
