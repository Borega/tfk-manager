from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from server.app.analysis.etl import normalize_events, parse_iso_utc
from server.app.analysis.metrics import compute_metrics


def _line_figure(title: str, x: list[str], y: list[int], color: str) -> dict[str, Any]:
    return {
        "data": [
            {
                "type": "scatter",
                "mode": "lines+markers",
                "name": title,
                "x": x,
                "y": y,
                "line": {"color": color, "width": 3},
                "marker": {"size": 7},
                "hovertemplate": "%{x}<br>%{y}<extra></extra>",
            }
        ],
        "layout": {
            "title": title,
            "margin": {"l": 40, "r": 20, "t": 50, "b": 40},
            "xaxis": {"title": "Time"},
            "yaxis": {"title": "Count"},
            "legend": {"orientation": "h"},
            "template": "plotly_white",
        },
        "config": {"responsive": True, "displaylogo": False},
    }


def _bar_figure(title: str, x: list[str], y: list[int], color: str) -> dict[str, Any]:
    return {
        "data": [
            {
                "type": "bar",
                "name": title,
                "x": x,
                "y": y,
                "marker": {"color": color},
                "hovertemplate": "%{x}<br>%{y}<extra></extra>",
            }
        ],
        "layout": {
            "title": title,
            "margin": {"l": 40, "r": 20, "t": 50, "b": 120},
            "xaxis": {"title": "Category", "tickangle": -30},
            "yaxis": {"title": "Count"},
            "template": "plotly_white",
        },
        "config": {"responsive": True, "displaylogo": False},
    }


def _build_figures(metrics_payload: dict[str, object]) -> dict[str, Any]:
    trends = metrics_payload.get("trends", {}) if isinstance(metrics_payload.get("trends"), dict) else {}
    security = metrics_payload.get("securityPolicy", {}) if isinstance(metrics_payload.get("securityPolicy"), dict) else {}
    behavior = metrics_payload.get("deviceBehavior", {}) if isinstance(metrics_payload.get("deviceBehavior"), dict) else {}

    dhcp_items = trends.get("dhcpLeaseCounts", []) if isinstance(trends.get("dhcpLeaseCounts"), list) else []
    fw_items = trends.get("firewallDenyCounts", []) if isinstance(trends.get("firewallDenyCounts"), list) else []
    blocked_vlan_items = security.get("topBlockedDomainsByVlan", []) if isinstance(security.get("topBlockedDomainsByVlan"), list) else []
    churn = behavior.get("churn", {}) if isinstance(behavior.get("churn"), dict) else {}

    dhcp_x = [str(item.get("bucketStart", "")) for item in dhcp_items if isinstance(item, dict)]
    dhcp_y = [int(item.get("eventCount", 0)) for item in dhcp_items if isinstance(item, dict)]
    fw_x = [str(item.get("bucketStart", "")) for item in fw_items if isinstance(item, dict)]
    fw_y = [int(item.get("eventCount", 0)) for item in fw_items if isinstance(item, dict)]

    blocked_labels = [
        f"{item.get('vlan', 'unknown')} | {item.get('url', 'unknown')}"
        for item in blocked_vlan_items[:12]
        if isinstance(item, dict)
    ]
    blocked_values = [
        int(item.get("blockCount", 0))
        for item in blocked_vlan_items[:12]
        if isinstance(item, dict)
    ]

    churn_x = ["New", "Departed", "Stable"]
    churn_y = [
        int(churn.get("newDevices", 0)),
        int(churn.get("departedDevices", 0)),
        int(churn.get("stableDevices", 0)),
    ]

    return {
        "dhcpLeaseTimeseries": _line_figure("DHCP Lease Activity", dhcp_x, dhcp_y, "#1f77b4"),
        "firewallDenyTimeseries": _line_figure("Firewall Deny Activity", fw_x, fw_y, "#d62728"),
        "topBlockedDomainsByVlan": _bar_figure("Top Blocked Domains by VLAN", blocked_labels, blocked_values, "#ff7f0e"),
        "deviceChurnSummary": _bar_figure("Device Churn", churn_x, churn_y, "#2ca02c"),
    }


def build_analysis_dashboard_payload(connection: Any, start_at: str, end_at: str, bucket_grain: str) -> dict[str, Any]:
    dataset = normalize_events(connection, start_at=start_at, end_at=end_at)
    start = parse_iso_utc(start_at)
    end = parse_iso_utc(end_at)
    metrics = compute_metrics(dataset=dataset, start_at=start, end_at=end, bucket_grain=bucket_grain)

    payload = {
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "window": {
            "startAt": start_at,
            "endAt": end_at,
            "bucketGrain": bucket_grain,
            "eventCount": len(dataset.events),
        },
        **metrics.payload,
    }
    payload["dashboards"] = _build_figures(payload)
    return payload
