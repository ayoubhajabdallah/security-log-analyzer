from collections import Counter, defaultdict
from datetime import datetime, timedelta


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


def find_ips_targeting_multiple_users(
    events: list[Event],
    minimum_users: int,
) -> dict[str, set[str]]:
    usernames_by_ip: dict[str, set[str]] = defaultdict(set)

    for _, ip_address, username, result in events:
        if result == "FAILED":
            usernames_by_ip[ip_address].add(username)

    return {
        ip_address: usernames
        for ip_address, usernames in usernames_by_ip.items()
        if len(usernames) >= minimum_users
    }


def parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )


def find_brute_force_windows(
    events: list[Event],
    threshold: int,
    window_minutes: int,
) -> dict[str, int]:
    failed_times_by_ip: dict[str, list[datetime]] = defaultdict(list)

    for timestamp, ip_address, _, result in events:
        if result == "FAILED":
            failed_times_by_ip[ip_address].append(
                parse_timestamp(timestamp)
            )

    suspicious_ips: dict[str, int] = {}
    time_window = timedelta(minutes=window_minutes)

    for ip_address, timestamps in failed_times_by_ip.items():
        timestamps.sort()
        left = 0
        maximum_attempts = 0

        for right, current_time in enumerate(timestamps):
            while current_time - timestamps[left] > time_window:
                left += 1

            attempts_in_window = right - left + 1
            maximum_attempts = max(
                maximum_attempts,
                attempts_in_window,
            )

        if maximum_attempts >= threshold:
            suspicious_ips[ip_address] = maximum_attempts

    return suspicious_ips