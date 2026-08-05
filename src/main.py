import json
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from pathlib import Path

from src.parser import load_events
from src.report import build_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "sample_auth.log"

DEFAULT_FAILED_LOGIN_THRESHOLD = 5
DEFAULT_MINIMUM_TARGETED_USERS = 2
DEFAULT_WINDOW_THRESHOLD = 3
DEFAULT_WINDOW_MINUTES = 2


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise ArgumentTypeError(
            "value must be a positive integer"
        ) from None

    if number < 1:
        raise ArgumentTypeError(
            "value must be a positive integer"
        )

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
        help="Total failed logins required to raise an alert.",
    )
    parser.add_argument(
        "--minimum-users",
        type=positive_integer,
        default=DEFAULT_MINIMUM_TARGETED_USERS,
        help="Targeted usernames required to raise an alert.",
    )
    parser.add_argument(
        "--window-threshold",
        type=positive_integer,
        default=DEFAULT_WINDOW_THRESHOLD,
        help="Failed logins inside the time window required for an alert.",
    )
    parser.add_argument(
        "--window-minutes",
        type=positive_integer,
        default=DEFAULT_WINDOW_MINUTES,
        help="Length of the brute-force detection window in minutes.",
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

    report = build_report(
        events=events,
        failed_threshold=arguments.failed_threshold,
        minimum_users=arguments.minimum_users,
        window_threshold=arguments.window_threshold,
        window_minutes=arguments.window_minutes,
    )

    if arguments.json:
        json_report = {
            "log_file": str(arguments.log_file),
            **report,
        }

        print(json.dumps(json_report, indent=2))
        return

    print(
        f"Loaded {report['total_events']} "
        "authentication events."
    )

    for ip_address, failed_attempts in report[
        "suspicious_ips"
    ].items():
        print(
            f"ALERT: {ip_address} has "
            f"{failed_attempts} failed login attempts."
        )

    for ip_address, usernames in report[
        "multi_user_ips"
    ].items():
        joined_usernames = ", ".join(usernames)
        print(
            f"ALERT: {ip_address} targeted multiple users: "
            f"{joined_usernames}."
        )

    for ip_address, failed_attempts in report[
        "brute_force_ips"
    ].items():
        print(
            f"ALERT: {ip_address} made "
            f"{failed_attempts} failed attempts within "
            f"{arguments.window_minutes} minutes."
        )

    for ip_address, anomaly in report[
        "ml_anomalies"
    ].items():
        print(
            f"ML ALERT: {ip_address} shows unusual behavior "
            f"(score: {anomaly['anomaly_score']}, "
            f"failures: {anomaly['failed_attempts']}, "
            f"users: {anomaly['unique_users']})."
        )


if __name__ == "__main__":
    main()