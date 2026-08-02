from collections import Counter


Event = tuple[str, str, str, str]


def find_suspicious_ips(
    events: list[Event],
    threshold: int,
) -> dict[str, int]:
    failed_attempts_by_ip = Counter(
        ip_address
        for _, ip_address, _, result in events
        if result == "FAILED"
    )

    return {
        ip_address: failed_attempts
        for ip_address, failed_attempts in failed_attempts_by_ip.items()
        if failed_attempts >= threshold
    }