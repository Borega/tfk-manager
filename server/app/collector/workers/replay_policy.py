from datetime import datetime, timedelta, timezone


SOURCE_POLICY = {
    "dhcp": {
        "pollIntervalSeconds": 120,
        "retryBaseSeconds": 10,
        "retryMaxSeconds": 180,
        "staleThresholdSeconds": 600,
        "fallbackGraceSeconds": 300,
    },
    "firewall": {
        "pollIntervalSeconds": 20,
        "retryBaseSeconds": 5,
        "retryMaxSeconds": 60,
        "staleThresholdSeconds": 75,
        "fallbackGraceSeconds": 45,
    },
    "webfilter": {
        "pollIntervalSeconds": 30,
        "retryBaseSeconds": 8,
        "retryMaxSeconds": 120,
        "staleThresholdSeconds": 180,
        "fallbackGraceSeconds": 90,
    },
}


def get_policy(source_key: str) -> dict[str, int]:
    if source_key not in SOURCE_POLICY:
        raise KeyError(f"Unknown source key: {source_key}")
    return SOURCE_POLICY[source_key]


def next_retry_delay_seconds(source_key: str, attempt: int) -> int:
    policy = get_policy(source_key)
    exponent = max(0, int(attempt))
    delay = policy["retryBaseSeconds"] * (2 ** exponent)
    return min(policy["retryMaxSeconds"], delay)


def next_retry_at(source_key: str, attempt: int, now_utc: datetime) -> str:
    delay = next_retry_delay_seconds(source_key, attempt)
    ts = now_utc.astimezone(timezone.utc) + timedelta(seconds=delay)
    return ts.isoformat().replace("+00:00", "Z")


def is_retry_ready(next_retry_at_iso: str | None, now_utc: datetime) -> bool:
    if not next_retry_at_iso:
        return True
    ts = datetime.fromisoformat(next_retry_at_iso.replace("Z", "+00:00"))
    return now_utc.astimezone(timezone.utc) >= ts.astimezone(timezone.utc)


def should_trigger_fallback(source_key: str, outage_seconds: int) -> bool:
    policy = get_policy(source_key)
    return int(outage_seconds) >= policy["fallbackGraceSeconds"]
