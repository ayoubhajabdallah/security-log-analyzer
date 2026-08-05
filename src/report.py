from typing import TypedDict

from src.analyzer import (
    Event,
    find_brute_force_windows,
    find_ips_targeting_multiple_users,
    find_suspicious_ips,
)


class AnalysisReport(TypedDict):
    total_events: int
    suspicious_ips: dict[str, int]
    multi_user_ips: dict[str, list[str]]
    brute_force_ips: dict[str, int]


def build_report(
    events: list[Event],
    failed_threshold: int,
    minimum_users: int,
    window_threshold: int,
    window_minutes: int,
) -> AnalysisReport:
    suspicious_ips = find_suspicious_ips(
        events,
        failed_threshold,
    )

    multi_user_ips = find_ips_targeting_multiple_users(
        events,
        minimum_users,
    )

    brute_force_ips = find_brute_force_windows(
        events,
        window_threshold,
        window_minutes,
    )

    return {
        "total_events": len(events),
        "suspicious_ips": suspicious_ips,
        "multi_user_ips": {
            ip_address: sorted(usernames)
            for ip_address, usernames in multi_user_ips.items()
        },
        "brute_force_ips": brute_force_ips,
    }