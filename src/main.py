from argparse import ArgumentParser, Namespace
from pathlib import Path

from src.analyzer import (
    find_ips_targeting_multiple_users,
    find_suspicious_ips,
)
from src.parser import load_events


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "sample_auth.log"
FAILED_LOGIN_THRESHOLD = 5
MINIMUM_TARGETED_USERS = 2


def parse_arguments() -> Namespace:
    parser = ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to the authentication log file.",
    )

    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    try:
        events = load_events(arguments.log_file)
    except FileNotFoundError:
        raise SystemExit(
            f"Error: log file not found: {arguments.log_file}"
        ) from None
    suspicious_ips = find_suspicious_ips(
        events,
        FAILED_LOGIN_THRESHOLD,
    )
    multi_user_ips = find_ips_targeting_multiple_users(
        events,
        MINIMUM_TARGETED_USERS,
    )

    print(f"Loaded {len(events)} authentication events.")

    for ip_address, failed_attempts in suspicious_ips.items():
        print(
            f"ALERT: {ip_address} has "
            f"{failed_attempts} failed login attempts."
        )

    for ip_address, usernames in multi_user_ips.items():
        sorted_usernames = ", ".join(sorted(usernames))
        print(
            f"ALERT: {ip_address} targeted multiple users: "
            f"{sorted_usernames}."
        )


if __name__ == "__main__":
    main()