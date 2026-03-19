import { describe, expect, it } from "vitest";
import { applySortToRows, compareBoolean, compareByColumn, compareIp, compareNullable, compareSegment, compareTimestamp, getSortIndicator, ipToNumber, toggleSort, type SortConfig } from "./tableSorting";

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

describe("applySortToRows", () => {
  interface TestRow {
    id: number;
    name: string;
    value: number;
  }

  const rows: TestRow[] = [
    { id: 1, name: "Charlie", value: 30 },
    { id: 2, name: "Alice", value: 20 },
    { id: 3, name: "Bob", value: 10 },
  ];

  it("returns original array unchanged when sortConfig is null (preserves default)", () => {
    const result = applySortToRows(rows, null);
    expect(result).toEqual(rows);
    // Should preserve order
    expect(result[0].name).toBe("Charlie");
    expect(result[1].name).toBe("Alice");
    expect(result[2].name).toBe("Bob");
  });

  it("sorts by numeric column ascending", () => {
    const sortConfig: SortConfig = { column: "value", direction: "asc" };
    const result = applySortToRows(rows, sortConfig);
    expect(result[0].value).toBe(10);
    expect(result[1].value).toBe(20);
    expect(result[2].value).toBe(30);
  });

  it("sorts by numeric column descending", () => {
    const sortConfig: SortConfig = { column: "value", direction: "desc" };
    const result = applySortToRows(rows, sortConfig);
    expect(result[0].value).toBe(30);
    expect(result[1].value).toBe(20);
    expect(result[2].value).toBe(10);
  });

  it("sorts by string column ascending", () => {
    const sortConfig: SortConfig = { column: "name", direction: "asc" };
    const result = applySortToRows(rows, sortConfig);
    expect(result[0].name).toBe("Alice");
    expect(result[1].name).toBe("Bob");
    expect(result[2].name).toBe("Charlie");
  });

  it("sorts by string column descending", () => {
    const sortConfig: SortConfig = { column: "name", direction: "desc" };
    const result = applySortToRows(rows, sortConfig);
    expect(result[0].name).toBe("Charlie");
    expect(result[1].name).toBe("Bob");
    expect(result[2].name).toBe("Alice");
  });

  it("does NOT mutate original array (immutability check)", () => {
    const originalFirst = rows[0];
    const sortConfig: SortConfig = { column: "name", direction: "asc" };
    
    const result = applySortToRows(rows, sortConfig);
    
    // Original array should still have same order
    expect(rows[0]).toBe(originalFirst);
    expect(rows[0].name).toBe("Charlie");
    
    // Result should be sorted
    expect(result[0].name).toBe("Alice");
  });

  it("integration test with realistic AnalysisDeviceRow-like data", () => {
    interface DeviceRow {
      ip: string;
      hostname: string;
      riskScore: number;
    }
    
    const devices: DeviceRow[] = [
      { ip: "10.0.0.3", hostname: "device-c", riskScore: 5 },
      { ip: "10.0.0.1", hostname: "device-a", riskScore: 10 },
      { ip: "10.0.0.2", hostname: "device-b", riskScore: 3 },
    ];
    
    // Sort by riskScore descending
    const sortConfig: SortConfig = { column: "riskScore", direction: "desc" };
    const result = applySortToRows(devices, sortConfig);
    
    expect(result[0].riskScore).toBe(10);
    expect(result[1].riskScore).toBe(5);
    expect(result[2].riskScore).toBe(3);
    
    // Original should be unchanged
    expect(devices[0].hostname).toBe("device-c");
  });
});

describe("getSortIndicator", () => {
  it("returns empty string when sortConfig is null", () => {
    expect(getSortIndicator(null, "riskScore")).toBe("");
  });

  it("returns empty string when different column is active", () => {
    const sortConfig: SortConfig = { column: "hostname", direction: "asc" };
    expect(getSortIndicator(sortConfig, "riskScore")).toBe("");
  });

  it("returns ' ↑' for ascending sort on active column", () => {
    const sortConfig: SortConfig = { column: "riskScore", direction: "asc" };
    expect(getSortIndicator(sortConfig, "riskScore")).toBe(" ↑");
  });

  it("returns ' ↓' for descending sort on active column", () => {
    const sortConfig: SortConfig = { column: "riskScore", direction: "desc" };
    expect(getSortIndicator(sortConfig, "riskScore")).toBe(" ↓");
  });
});

describe("compareIp", () => {
  it("sorts IPs in numeric order (10.0.0.2 before 10.0.0.10)", () => {
    // Numeric comparison: 10.0.0.2 (167772162) < 10.0.0.10 (167772170)
    const result = compareIp("10.0.0.2", "10.0.0.10");
    expect(result).toBeLessThan(0);
  });

  it("sorts large and small IPs correctly (10.0.0.10 before 192.168.1.1)", () => {
    // 167772170 < 3232235777
    const result = compareIp("10.0.0.10", "192.168.1.1");
    expect(result).toBeLessThan(0);
  });

  it("handles invalid IPs by treating them as 0", () => {
    // compareIp("invalid", "10.0.0.1") should be negative (0 < valid IP)
    const result = compareIp("invalid", "10.0.0.1");
    expect(result).toBeLessThan(0);
  });

  it("sorts multiple IPs in correct numeric order", () => {
    // Array: ["10.0.0.10", "10.0.0.2", "192.168.1.1"]
    // Sort to: ["10.0.0.2", "10.0.0.10", "192.168.1.1"]
    const ips = ["10.0.0.10", "10.0.0.2", "192.168.1.1"];
    const sorted = ips.slice().sort((a, b) => compareIp(a, b));
    expect(sorted[0]).toBe("10.0.0.2");
    expect(sorted[1]).toBe("10.0.0.10");
    expect(sorted[2]).toBe("192.168.1.1");
  });
});

describe("compareTimestamp", () => {
  const mockToTimeMillis = (value: string): number => {
    if (!value) return 0;
    const ts = Date.parse(value);
    return Number.isNaN(ts) ? 0 : ts;
  };

  it("sorts ISO timestamps correctly (earlier date before later)", () => {
    // Earlier time: 09:00, Later time: 10:00
    const earlierTime = "2024-01-01T09:00:00Z";
    const laterTime = "2024-01-01T10:00:00Z";
    const result = compareTimestamp(earlierTime, laterTime, mockToTimeMillis);
    expect(result).toBeLessThan(0);
  });

  it("places empty strings last", () => {
    // Valid time > empty time (0)
    const result = compareTimestamp("2024-01-01T10:00:00Z", "", mockToTimeMillis);
    expect(result).toBeGreaterThan(0);
  });

  it("handles identical timestamps (returns 0)", () => {
    const ts = "2024-01-01T10:00:00Z";
    const result = compareTimestamp(ts, ts, mockToTimeMillis);
    expect(result).toBe(0);
  });
});

describe("compareBoolean", () => {
  it("sorts true before false (descending default)", () => {
    // compareBoolean(true, false) should return < 0
    const result = compareBoolean(true, false);
    expect(result).toBeLessThan(0);
  });

  it("sorts false after true", () => {
    // compareBoolean(false, true) should return > 0
    const result = compareBoolean(false, true);
    expect(result).toBeGreaterThan(0);
  });

  it("returns 0 for identical values", () => {
    // compareBoolean(true, true) and compareBoolean(false, false)
    expect(compareBoolean(true, true)).toBe(0);
    expect(compareBoolean(false, false)).toBe(0);
  });
});

describe("compareSegment", () => {
  it("orders Static Gruen first", () => {
    // compareSegment("Static Gruen", "Static BYOD") should return < 0
    const result = compareSegment("Static Gruen", "Static BYOD");
    expect(result).toBeLessThan(0);
  });

  it("orders Static BYOD second", () => {
    // compareSegment("Static BYOD", "Dynamic Gruen") should return < 0
    const result = compareSegment("Static BYOD", "Dynamic Gruen");
    expect(result).toBeLessThan(0);
  });

  it("orders Dynamic Gruen third", () => {
    // compareSegment("Dynamic Gruen", "Dynamic BYOD") should return < 0
    const result = compareSegment("Dynamic Gruen", "Dynamic BYOD");
    expect(result).toBeLessThan(0);
  });

  it("orders Dynamic BYOD fourth", () => {
    // compareSegment("Dynamic BYOD", "Unknown") should return < 0
    const result = compareSegment("Dynamic BYOD", "Unknown");
    expect(result).toBeLessThan(0);
  });

  it("orders Unknown last", () => {
    // compareSegment("Static Gruen", "Unknown") should return < 0
    // compareSegment("Unknown", "Static Gruen") should return > 0
    expect(compareSegment("Static Gruen", "Unknown")).toBeLessThan(0);
    expect(compareSegment("Unknown", "Static Gruen")).toBeGreaterThan(0);
  });

  it("handles all segments in business order", () => {
    const segments = ["Unknown", "Dynamic BYOD", "Static Gruen", "Dynamic Gruen", "Static BYOD"];
    // After sorting with compareSegment, should be in business order:
    const sorted = segments.slice().sort((a, b) => compareSegment(a, b));
    expect(sorted[0]).toBe("Static Gruen");
    expect(sorted[1]).toBe("Static BYOD");
    expect(sorted[2]).toBe("Dynamic Gruen");
    expect(sorted[3]).toBe("Dynamic BYOD");
    expect(sorted[4]).toBe("Unknown");
  });
});

describe("applySortToRows with special comparators", () => {
  interface DeviceRow {
    ip: string;
    hostname: string;
    lastSeen: string;
    hasDualBlock: boolean;
    segment: string;
    riskScore: number;
  }

  const mockToTimeMillis = (value: string): number => {
    if (!value) return 0;
    const ts = Date.parse(value);
    return Number.isNaN(ts) ? 0 : ts;
  };

  const devices: DeviceRow[] = [
    {
      ip: "192.168.1.1",
      hostname: "host-1",
      lastSeen: "2024-01-01T10:00:00Z",
      hasDualBlock: true,
      segment: "Dynamic BYOD",
      riskScore: 5,
    },
    {
      ip: "10.0.0.2",
      hostname: "host-2",
      lastSeen: "2024-01-01T09:00:00Z",
      hasDualBlock: false,
      segment: "Static Gruen",
      riskScore: 10,
    },
    {
      ip: "10.0.0.10",
      hostname: "host-3",
      lastSeen: "2024-01-01T11:00:00Z",
      hasDualBlock: true,
      segment: "Unknown",
      riskScore: 3,
    },
  ];

  it("uses IP comparator for 'ip' column (numeric sort)", () => {
    const sortConfig: SortConfig = { column: "ip", direction: "asc" };
    const result = applySortToRows(devices, sortConfig, mockToTimeMillis);
    // Should be numeric order: 10.0.0.2, 10.0.0.10, 192.168.1.1
    expect(result[0].ip).toBe("10.0.0.2");
    expect(result[1].ip).toBe("10.0.0.10");
    expect(result[2].ip).toBe("192.168.1.1");
  });

  it("uses IP comparator descending for 'ip' column", () => {
    const sortConfig: SortConfig = { column: "ip", direction: "desc" };
    const result = applySortToRows(devices, sortConfig, mockToTimeMillis);
    // Should be reverse numeric order: 192.168.1.1, 10.0.0.10, 10.0.0.2
    expect(result[0].ip).toBe("192.168.1.1");
    expect(result[1].ip).toBe("10.0.0.10");
    expect(result[2].ip).toBe("10.0.0.2");
  });

  it("uses timestamp comparator for 'lastSeen' column", () => {
    const sortConfig: SortConfig = { column: "lastSeen", direction: "asc" };
    const result = applySortToRows(devices, sortConfig, mockToTimeMillis);
    // Should be chronological: 09:00, 10:00, 11:00
    expect(result[0].hostname).toBe("host-2");
    expect(result[1].hostname).toBe("host-1");
    expect(result[2].hostname).toBe("host-3");
  });

  it("uses boolean comparator for 'hasDualBlock' column", () => {
    const sortConfig: SortConfig = { column: "hasDualBlock", direction: "asc" };
    const result = applySortToRows(devices, sortConfig, mockToTimeMillis);
    // For boolean, asc should still sort true before false
    // host-1 (true), host-3 (true) come before host-2 (false)
    expect(result[0].hasDualBlock).toBe(true);
    expect(result[1].hasDualBlock).toBe(true);
    expect(result[2].hasDualBlock).toBe(false);
  });

  it("uses segment comparator for 'segment' column", () => {
    const sortConfig: SortConfig = { column: "segment", direction: "asc" };
    const result = applySortToRows(devices, sortConfig, mockToTimeMillis);
    // Business order: Static Gruen, Static BYOD, Dynamic Gruen, Dynamic BYOD, Unknown
    // Our devices: Dynamic BYOD (0), Static Gruen (1), Unknown (2)
    expect(result[0].segment).toBe("Static Gruen");
    expect(result[1].segment).toBe("Dynamic BYOD");
    expect(result[2].segment).toBe("Unknown");
  });

  it("falls back to default comparison for other columns", () => {
    const sortConfig: SortConfig = { column: "riskScore", direction: "asc" };
    const result = applySortToRows(devices, sortConfig, mockToTimeMillis);
    // Should sort numerically: 3, 5, 10
    expect(result[0].riskScore).toBe(3);
    expect(result[1].riskScore).toBe(5);
    expect(result[2].riskScore).toBe(10);
  });
});
