import { describe, expect, it } from "vitest";
import { buildAnalysisIdentityGraph, type AnalysisIdentityObservation } from "./analysisIdentityGraph";

describe("analysisIdentityGraph", () => {
  it("returns deterministic node and link ordering for repeated snapshots", () => {
    const snapshot: AnalysisIdentityObservation[] = [
      {
        sourceType: "static-lease",
        ip: "10.6.168.50",
        mac: "AA:BB:CC:DD:EE:FF",
        hostname: "Teacher-Laptop",
      },
      {
        sourceType: "webfilter-log",
        ip: "10.6.168.50",
        user: "teacher01",
      },
      {
        sourceType: "dynamic-lease",
        ip: "10.6.168.51",
        mac: "AA:BB:CC:DD:EE:01",
        hostname: "Student-Tablet",
      },
    ];

    const first = buildAnalysisIdentityGraph(snapshot);
    const second = buildAnalysisIdentityGraph(snapshot);

    expect(second).toEqual(first);
    expect(first.nodes.map((node) => node.id)).toEqual([
      "ip:10.6.168.50",
      "ip:10.6.168.51",
      "mac:aa:bb:cc:dd:ee:01",
      "mac:aa:bb:cc:dd:ee:ff",
      "hostname:student-tablet",
      "hostname:teacher-laptop",
      "user:teacher01",
    ]);
    expect(first.links.map((link) => link.id)).toEqual([...first.links.map((link) => link.id)].sort());
  });

  it("emits confidence metadata for each graph link", () => {
    const graph = buildAnalysisIdentityGraph([
      {
        sourceType: "static-lease",
        ip: "10.6.168.77",
        mac: "00:11:22:33:44:55",
        hostname: "lab-desktop",
        user: "teacher",
      },
      {
        sourceType: "webfilter-log",
        ip: "10.6.168.77",
        user: "teacher",
      },
    ]);

    const ipToUserLink = graph.links.find((link) =>
      link.id.includes("ip:10.6.168.77") && link.id.includes("user:teacher"),
    );

    expect(ipToUserLink).toBeDefined();
    expect(ipToUserLink?.evidenceCount).toBeGreaterThan(0);
    expect(ipToUserLink?.confidence).toMatch(/high|medium|low/);
  });
});
