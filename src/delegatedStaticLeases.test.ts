import { describe, expect, it } from "vitest";

import {
  normalizeDelegatedStaticIface,
  splitDelegatedStaticLeases,
  type DelegatedStaticLeaseRow,
} from "./delegatedStaticLeases";

describe("normalizeDelegatedStaticIface", () => {
  it("normalizes lan aliases", () => {
    expect(normalizeDelegatedStaticIface("lan")).toBe("lan");
    expect(normalizeDelegatedStaticIface("Gruen")).toBe("lan");
  });

  it("normalizes opt4 aliases", () => {
    expect(normalizeDelegatedStaticIface("opt4")).toBe("opt4");
    expect(normalizeDelegatedStaticIface("WLANBYOD")).toBe("opt4");
  });

  it("returns empty iface for unknown values", () => {
    expect(normalizeDelegatedStaticIface("unknown")).toBe("");
    expect(normalizeDelegatedStaticIface(undefined)).toBe("");
  });
});

describe("splitDelegatedStaticLeases", () => {
  it("routes rows by normalized iface and counts unknown rows", () => {
    const rows: DelegatedStaticLeaseRow[] = [
      { hostname: "lan-1", mac: "00:11:22:33:44:55", ip: "10.6.168.10", iface: "lan" },
      { hostname: "lan-2", mac: "00:11:22:33:44:66", ip: "10.6.168.11", iface: "Gruen" },
      { hostname: "opt4-1", mac: "AA:BB:CC:DD:EE:FF", ip: "10.8.4.20", iface: "opt4" },
      { hostname: "opt4-2", mac: "AA:BB:CC:DD:EE:01", ip: "10.8.4.21", iface: "WLANBYOD" },
      { hostname: "unknown-1", mac: "AA:BB:CC:DD:EE:02", ip: "10.8.4.22", iface: "unknown" },
    ];

    const split = splitDelegatedStaticLeases(rows);

    expect(split.opt4Rows.map((row) => row.hostname)).toEqual(["opt4-1", "opt4-2"]);
    expect(split.lanRows.map((row) => row.hostname)).toEqual(["lan-1", "lan-2", "unknown-1"]);
    expect(split.unknownIfaceCount).toBe(1);
  });
});
