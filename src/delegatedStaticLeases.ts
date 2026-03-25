export type DelegatedStaticLeaseRow = {
  hostname: string;
  mac: string;
  ip: string;
  iface?: string;
};

export function normalizeDelegatedStaticIface(value: string | undefined): "lan" | "opt4" | "" {
  const text = (value ?? "").trim().toLowerCase();
  if (text === "lan" || text === "gruen") return "lan";
  if (text === "opt4" || text === "wlanbyod") return "opt4";
  return "";
}

export function splitDelegatedStaticLeases(rows: DelegatedStaticLeaseRow[]): {
  lanRows: DelegatedStaticLeaseRow[];
  opt4Rows: DelegatedStaticLeaseRow[];
  unknownIfaceCount: number;
} {
  const lanRows: DelegatedStaticLeaseRow[] = [];
  const opt4Rows: DelegatedStaticLeaseRow[] = [];
  let unknownIfaceCount = 0;

  rows.forEach((row) => {
    const iface = normalizeDelegatedStaticIface(row.iface);
    if (iface === "opt4") {
      opt4Rows.push(row);
      return;
    }
    if (!iface) {
      unknownIfaceCount += 1;
    }
    lanRows.push(row);
  });

  return {
    lanRows,
    opt4Rows,
    unknownIfaceCount,
  };
}
