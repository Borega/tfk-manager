import { describe, expect, it } from "vitest";
import { parseWebfilterStatus } from "./webfilterStatus";

describe("parseWebfilterStatus", () => {
  it("maps no-login sentinel for webfilter source", () => {
    const result = parseWebfilterStatus(
      "Login failed - redirected back to login page",
      "webfilter-ui",
      "webfilter-80-1920",
    );
    expect(result.status).toBe("no-login");
    expect(result.recoverable).toBe(true);
    expect(result.interpreted).toBe(true);
  });

  it("maps no-connection sentinel for webfilter source", () => {
    const result = parseWebfilterStatus(
      "Failed to fetch logs: connection refused",
      "webfilter-ui",
      "webfilter-80-1920",
    );
    expect(result.status).toBe("no-connection");
    expect(result.recoveryAction).toContain("Retry");
  });

  it("maps no-rights sentinel for webfilter source", () => {
    const result = parseWebfilterStatus(
      "No rights for this operation",
      "webfilter-ui",
      "webfilter-80-1920",
    );
    expect(result.status).toBe("no-rights");
    expect(result.recoverable).toBe(false);
  });

  it("does not interpret sentinels for opnsense-api source", () => {
    const raw = "no login";
    const result = parseWebfilterStatus(raw, "opnsense-api", "opnsense-81");
    expect(result.status).toBe("unknown");
    expect(result.interpreted).toBe(false);
    expect(result.message).toBe(raw);
  });
});
