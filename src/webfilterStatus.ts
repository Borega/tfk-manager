export type WebfilterStatusSource = "webfilter-ui" | "opnsense-api" | "firewall-stream" | "leases";

export type WebfilterStatusOrigin = "webfilter-80-1920" | "opnsense-81";

export type WebfilterStatusCode = "ok" | "no-login" | "no-connection" | "no-rights" | "unknown";

export type WebfilterStatusResult = {
  status: WebfilterStatusCode;
  message: string;
  recoverable: boolean;
  recoveryAction: string;
  interpreted: boolean;
};

export function parseWebfilterStatus(
  raw: string,
  source: WebfilterStatusSource,
  origin: WebfilterStatusOrigin,
): WebfilterStatusResult {
  const fallbackMessage = raw.trim() || "Unknown error";

  // Sentinel mapping must only apply to the webfilter chain (ports 80/1920).
  if (source !== "webfilter-ui" || origin !== "webfilter-80-1920") {
    return {
      status: "unknown",
      message: fallbackMessage,
      recoverable: false,
      recoveryAction: "None",
      interpreted: false,
    };
  }

  const value = fallbackMessage.toLowerCase();

  if (value === "ok") {
    return {
      status: "ok",
      message: "Webfilter logs fetched successfully.",
      recoverable: false,
      recoveryAction: "None",
      interpreted: true,
    };
  }

  if (
    value.includes("no login")
    || value.includes("not authenticated")
    || value.includes("redirected back to login")
  ) {
    return {
      status: "no-login",
      message: "Webfilter login is no longer valid. Re-save MSD credentials and fetch logs again.",
      recoverable: true,
      recoveryAction: "Re-authenticate to webfilter",
      interpreted: true,
    };
  }

  if (
    value.includes("no connection to webfilter")
    || value.includes("failed to fetch logs")
    || value.includes("connection refused")
    || value.includes("timed out")
    || value.includes("timeout")
  ) {
    return {
      status: "no-connection",
      message: "Cannot reach webfilter right now (ports 80/1920). Check service/network and retry.",
      recoverable: true,
      recoveryAction: "Retry after connectivity check",
      interpreted: true,
    };
  }

  if (
    value.includes("no rights")
    || value.includes("forbidden")
    || value.includes("http 403")
  ) {
    return {
      status: "no-rights",
      message: "Webfilter user has insufficient rights to read logs.",
      recoverable: false,
      recoveryAction: "Grant required MSD permissions",
      interpreted: true,
    };
  }

  return {
    status: "unknown",
    message: fallbackMessage,
    recoverable: false,
    recoveryAction: "Inspect diagnostics and backend output",
    interpreted: true,
  };
}
