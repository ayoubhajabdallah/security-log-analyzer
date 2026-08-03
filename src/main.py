import json
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from pathlib import Path

from src.analyzer import (
    find_ips_targeting_multiple_users,
    find_suspicious_ips,
)
from src.parser import load_events


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "sample_auth.log"
DEFAULT_FAILED_LOGIN_THRESHOLD = 5
DEFAULT_MINIMUM_TARGETED_USERS = 2


def positive_integer(value: str) -> int:
    number = int(value)

    if number < 1:
        raise ArgumentTypeError("value must be a positive integer")

    return number


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
    parser.add_argument(
        "--failed-threshold",
        type=positive_integer,
        default=DEFAULT_FAILED_LOGIN_THRESHOLD,
        help="Number of failed logins required to raise an alert.",
    )
    parser.add_argument(
        "--minimum-users",
        type=positive_integer,
        default=DEFAULT_MINIMUM_TARGETED_USERS,
        help="Number of targeted usernames required to raise an alert.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the analysis result as JSON.",
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
    except ValueError as error:
        raise SystemExit(
            f"Error: invalid log format: {error}"
        ) from None

    suspicious_ips = find_suspicious_ips(
        events,
        arguments.failed_threshold,
    )
    multi_user_ips = find_ips_targeting_multiple_users(
        events,
        arguments.minimum_users,
    )

    if arguments.json:
        report = {
            "log_file": str(arguments.log_file),
            "total_events": len(events),
            "suspicious_ips": suspicious_ips,
            "multi_user_ips": {
                ip_address: sorted(usernames)
                for ip_address, usernames in multi_user_ips.items()
            },
        }

        print(json.dumps(report, indent=2))
        return

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