from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import mean

from server.app.analysis.etl import NormalizedDataset, bucket_iso, infer_vlan_from_ip


VENDOR_PREFIX = {
    "00:1A:2B": "Cisco",
    "3C:5A:B4": "Google",
    "40:B0:34": "Apple",
    "44:65:0D": "Dell",
    "7C:8B:CA": "Intel",
    "B8:27:EB": "Raspberry Pi",
    "D8:BB:C1": "Samsung",
}


def _vendor_from_mac(mac: str) -> str:
    text = (mac or "").strip().upper().replace("-", ":")
    if len(text) < 8:
        return "Unknown"
    return VENDOR_PREFIX.get(text[:8], "Unknown")


def _is_blocked_action(action: str) -> bool:
    lowered = (action or "").strip().lower()
    return lowered in {"block", "blocked", "deny", "denied", "drop"}


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _percent(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 1)


def _pool_capacity(vlan: str) -> int:
    if vlan == "lan":
        return 1024
    if vlan == "opt4":
        return 512
    if vlan == "mgmt":
        return 254
    return 256


@dataclass(slots=True)
class MetricsBundle:
    payload: dict[str, object]


def compute_metrics(dataset: NormalizedDataset, start_at: datetime, end_at: datetime, bucket_grain: str) -> MetricsBundle:
    dhcp_series: dict[str, int] = defaultdict(int)
    fw_deny_series: dict[str, int] = defaultdict(int)
    blocked_category_counter: Counter[str] = Counter()
    blocked_url_counter: Counter[str] = Counter()
    blocked_url_by_vlan_counter: Counter[tuple[str, str]] = Counter()
    fw_deny_by_vlan: Counter[str] = Counter()

    ip_to_vlan: dict[str, str] = {}
    ip_to_mac: dict[str, str] = {}
    mac_to_vendor: dict[str, str] = {}

    lease_durations_minutes: list[int] = []
    source_entity_seen: dict[str, list[datetime]] = defaultdict(list)
    source_entity_vlan_sequence: dict[str, list[str]] = defaultdict(list)
    gruen_active_by_bucket: dict[str, set[str]] = defaultdict(set)

    per_device: dict[str, dict[str, object]] = {}
    anomalies: list[dict[str, object]] = []
    misconfigurations: list[dict[str, object]] = []

    for event in dataset.dhcp_events:
        bucket = bucket_iso(event.occurred_at, bucket_grain)
        dhcp_series[bucket] += 1

        ip = str(event.payload.get("ip", "")).strip()
        mac = str(event.payload.get("mac", "")).strip()
        hostname = str(event.payload.get("hostname", "")).strip()
        vlan = infer_vlan_from_ip(ip)

        if vlan == "lan" and ip:
            gruen_active_by_bucket[bucket].add(ip)

        if ip:
            ip_to_vlan[ip] = vlan
        if ip and mac:
            ip_to_mac[ip] = mac
        if mac:
            mac_to_vendor[mac] = _vendor_from_mac(mac)

        device_identity = mac or ip or event.source_entity_id
        source_entity_seen[device_identity].append(event.occurred_at)
        if vlan:
            source_entity_vlan_sequence[device_identity].append(vlan)

        lease_end_value = str(event.payload.get("leaseEnd", "")).strip()
        if lease_end_value:
            try:
                lease_end = datetime.fromisoformat(lease_end_value.replace("Z", "+00:00")).astimezone(timezone.utc)
                delta = lease_end - event.occurred_at
                minutes = int(delta.total_seconds() // 60)
                if 0 <= minutes <= 60 * 24 * 14:
                    lease_durations_minutes.append(minutes)
            except ValueError:
                pass

        device_key = mac or ip or event.source_entity_id
        current = per_device.setdefault(
            device_key,
            {
                "deviceId": device_key,
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vlan": vlan,
                "vendor": _vendor_from_mac(mac),
                "leaseEvents": 0,
                "firewallDenies": 0,
                "blockedUrls": 0,
                "lastSeenAt": event.occurred_at.isoformat().replace("+00:00", "Z"),
            },
        )
        current["leaseEvents"] = _safe_int(current.get("leaseEvents")) + 1
        current["lastSeenAt"] = event.occurred_at.isoformat().replace("+00:00", "Z")

    for event in dataset.firewall_events:
        action = str(event.payload.get("action", ""))
        is_deny = _is_blocked_action(action)
        if not is_deny:
            continue

        bucket = bucket_iso(event.occurred_at, bucket_grain)
        fw_deny_series[bucket] += 1

        src_ip = str(event.payload.get("src", "")).strip()
        vlan = ip_to_vlan.get(src_ip) or infer_vlan_from_ip(src_ip)
        fw_deny_by_vlan[vlan] += 1

        device_identity = src_ip or event.source_entity_id
        source_entity_seen[device_identity].append(event.occurred_at)
        source_entity_vlan_sequence[device_identity].append(vlan)

        device_key = ip_to_mac.get(src_ip) or src_ip or event.source_entity_id
        current = per_device.setdefault(
            device_key,
            {
                "deviceId": device_key,
                "mac": ip_to_mac.get(src_ip, ""),
                "ip": src_ip,
                "hostname": "",
                "vlan": vlan,
                "vendor": _vendor_from_mac(ip_to_mac.get(src_ip, "")),
                "leaseEvents": 0,
                "firewallDenies": 0,
                "blockedUrls": 0,
                "lastSeenAt": event.occurred_at.isoformat().replace("+00:00", "Z"),
            },
        )
        current["firewallDenies"] = _safe_int(current.get("firewallDenies")) + 1
        current["lastSeenAt"] = event.occurred_at.isoformat().replace("+00:00", "Z")

        if vlan == "unknown" and src_ip:
            misconfigurations.append(
                {
                    "type": "firewall_deny_unknown_vlan",
                    "severity": "medium",
                    "detail": f"Firewall deny from {src_ip} is not mapped to a known VLAN.",
                    "eventId": event.event_id,
                    "occurredAt": event.occurred_at.isoformat().replace("+00:00", "Z"),
                }
            )

    for event in dataset.webfilter_events:
        action = str(event.payload.get("action", ""))
        if not _is_blocked_action(action):
            continue

        url = str(event.payload.get("url", "")).strip() or "unknown"
        category = str(event.payload.get("category", "")).strip() or "uncategorized"
        user = str(event.payload.get("user", "")).strip()
        user_vlan = ip_to_vlan.get(user) or infer_vlan_from_ip(user)

        blocked_category_counter[category] += 1
        blocked_url_counter[url] += 1
        blocked_url_by_vlan_counter[(user_vlan, url)] += 1

        if category == "uncategorized":
            misconfigurations.append(
                {
                    "type": "webfilter_missing_category",
                    "severity": "low",
                    "detail": f"Blocked URL {url} has no category mapping.",
                    "eventId": event.event_id,
                    "occurredAt": event.occurred_at.isoformat().replace("+00:00", "Z"),
                }
            )

        if user:
            device_key = ip_to_mac.get(user) or user
            current = per_device.setdefault(
                device_key,
                {
                    "deviceId": device_key,
                    "mac": ip_to_mac.get(user, ""),
                    "ip": user,
                    "hostname": "",
                    "vlan": user_vlan,
                    "vendor": _vendor_from_mac(ip_to_mac.get(user, "")),
                    "leaseEvents": 0,
                    "firewallDenies": 0,
                    "blockedUrls": 0,
                    "lastSeenAt": event.occurred_at.isoformat().replace("+00:00", "Z"),
                },
            )
            current["blockedUrls"] = _safe_int(current.get("blockedUrls")) + 1
            current["lastSeenAt"] = event.occurred_at.isoformat().replace("+00:00", "Z")

        device_identity = user or event.source_entity_id
        source_entity_seen[device_identity].append(event.occurred_at)
        source_entity_vlan_sequence[device_identity].append(user_vlan)

    fw_deny_values = list(fw_deny_series.values())
    fw_mean = mean(fw_deny_values) if fw_deny_values else 0.0
    threshold = max(10.0, fw_mean * 2.0)
    for bucket, count in sorted(fw_deny_series.items()):
        if count >= threshold:
            anomalies.append(
                {
                    "type": "deny_spike",
                    "severity": "high",
                    "detail": f"Firewall deny spike detected with {count} denies.",
                    "bucketStart": bucket,
                    "count": count,
                }
            )

    window_seconds = max(1, int((end_at - start_at).total_seconds()))
    churn_threshold = timedelta(seconds=max(900, window_seconds // 4))
    cutoff_new = end_at - churn_threshold

    new_devices = 0
    departed_devices = 0
    stable_devices = 0
    vlan_transitions: list[dict[str, object]] = []

    for entity_id, seen_list in source_entity_seen.items():
        if not seen_list:
            continue
        ordered_seen = sorted(seen_list)
        first_seen = ordered_seen[0]
        last_seen = ordered_seen[-1]

        if first_seen >= cutoff_new:
            new_devices += 1
        elif last_seen < cutoff_new:
            departed_devices += 1
        else:
            stable_devices += 1

        sequence = [value for value in source_entity_vlan_sequence.get(entity_id, []) if value]
        transitions = 0
        prev = None
        last_transition = None
        for vlan in sequence:
            if prev is not None and vlan != prev:
                transitions += 1
                last_transition = vlan
            prev = vlan

        if transitions > 0:
            vlan_transitions.append(
                {
                    "entityId": entity_id,
                    "transitionCount": transitions,
                    "lastVlan": last_transition,
                    "lastOccurredAt": last_seen.isoformat().replace("+00:00", "Z"),
                }
            )

    active_by_vlan: Counter[str] = Counter()
    for item in per_device.values():
        vlan = str(item.get("vlan", "unknown"))
        active_by_vlan[vlan] += 1

    vlan_pool_utilization = [
        {
            "vlan": vlan,
            "activeDevices": count,
            "poolCapacity": _pool_capacity(vlan),
            "poolUsedPercent": _percent(count, _pool_capacity(vlan)),
        }
        for vlan, count in sorted(active_by_vlan.items())
    ]

    network_load = []
    for vlan, active in sorted(active_by_vlan.items()):
        denies = fw_deny_by_vlan.get(vlan, 0)
        blocked = sum(value for (item_vlan, _), value in blocked_url_by_vlan_counter.items() if item_vlan == vlan)
        network_load.append(
            {
                "vlan": vlan,
                "activeDevices": active,
                "firewallDenies": denies,
                "blockedRequests": blocked,
                "loadScore": round(active + (denies * 0.6) + (blocked * 0.4), 1),
            }
        )

    gruen_peak_recorded = max((len(ips) for ips in gruen_active_by_bucket.values()), default=0)

    vendor_counter: Counter[str] = Counter()
    for item in per_device.values():
        vendor_counter[str(item.get("vendor", "Unknown"))] += 1

    lease_duration_distribution = {
        "0-30m": 0,
        "30-120m": 0,
        "2-8h": 0,
        "8h+": 0,
    }
    for minutes in lease_durations_minutes:
        if minutes < 30:
            lease_duration_distribution["0-30m"] += 1
        elif minutes < 120:
            lease_duration_distribution["30-120m"] += 1
        elif minutes < 480:
            lease_duration_distribution["2-8h"] += 1
        else:
            lease_duration_distribution["8h+"] += 1

    top_blocked_by_vlan = [
        {
            "vlan": vlan,
            "url": url,
            "blockCount": count,
        }
        for (vlan, url), count in blocked_url_by_vlan_counter.most_common(25)
    ]

    per_blocked_url = [
        {
            "url": url,
            "blockCount": count,
        }
        for url, count in blocked_url_counter.most_common(50)
    ]

    per_device_rows = sorted(
        per_device.values(),
        key=lambda row: (_safe_int(row.get("firewallDenies")) + _safe_int(row.get("blockedUrls")), _safe_int(row.get("leaseEvents"))),
        reverse=True,
    )[:100]

    churn_total = new_devices + departed_devices + stable_devices
    churn_summary = {
        "newDevices": new_devices,
        "departedDevices": departed_devices,
        "stableDevices": stable_devices,
        "churnRatePercent": _percent(new_devices + departed_devices, churn_total),
    }

    if churn_summary["churnRatePercent"] >= 35:
        anomalies.append(
            {
                "type": "high_churn",
                "severity": "medium",
                "detail": f"Device churn is elevated at {churn_summary['churnRatePercent']}%.",
                "churnRatePercent": churn_summary["churnRatePercent"],
            }
        )

    payload = {
        "trends": {
            "dhcpLeaseCounts": [{"bucketStart": key, "eventCount": value} for key, value in sorted(dhcp_series.items())],
            "firewallDenyCounts": [{"bucketStart": key, "eventCount": value} for key, value in sorted(fw_deny_series.items())],
        },
        "networkInfrastructure": {
            "vlanIpPoolUtilization": vlan_pool_utilization,
            "networkLoad": network_load,
            "gruenPeakRecorded": gruen_peak_recorded,
        },
        "deviceBehavior": {
            "churn": churn_summary,
            "deviceTypes": [{"vendor": vendor, "count": count} for vendor, count in vendor_counter.most_common(12)],
            "vlanTransitions": sorted(vlan_transitions, key=lambda item: int(item["transitionCount"]), reverse=True)[:25],
            "leaseDurationDistribution": [{"bucket": key, "count": value} for key, value in lease_duration_distribution.items()],
            "perDevice": per_device_rows,
            "perBlockedUrl": per_blocked_url,
        },
        "securityPolicy": {
            "firewallDeniesByVlan": [{"vlan": vlan, "count": count} for vlan, count in fw_deny_by_vlan.most_common()],
            "blockedCategories": [{"category": category, "count": count} for category, count in blocked_category_counter.most_common(20)],
            "anomalousEvents": anomalies[:30],
            "misconfigurations": misconfigurations[:40],
            "topBlockedDomainsByVlan": top_blocked_by_vlan,
        },
    }

    suggestions: list[str] = []
    if any(item.get("poolUsedPercent", 0) >= 75 for item in vlan_pool_utilization):
        suggestions.append("At least one VLAN pool exceeds 75% utilization. Consider expanding the pool or reducing static assignments.")
    if churn_summary["churnRatePercent"] >= 30:
        suggestions.append("High device churn detected. Inspect onboarding flows and temporary device policies.")
    if any(item.get("severity") == "high" for item in anomalies):
        suggestions.append("High-severity deny spikes detected. Validate firewall rule ordering and investigate noisy sources.")
    if misconfigurations:
        suggestions.append("Potential misconfiguration signals found. Review unknown VLAN deny sources and uncategorized webfilter blocks.")

    payload["suggestions"] = suggestions
    return MetricsBundle(payload=payload)
