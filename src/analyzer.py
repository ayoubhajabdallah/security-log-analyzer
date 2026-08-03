from collections import Counter, defaultdict


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