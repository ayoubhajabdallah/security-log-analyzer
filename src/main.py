from pathlib import Path

from src.analyzer import find_suspicious_ips


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "data" / "sample_auth.log"
FAILED_LOGIN_THRESHOLD = 5


def parse_log_line(line: str) -> tuple[str, str, str, str]:
    timestamp, ip_address, username, result = line.split(",")
    return timestamp, ip_address, username, result


def main() -> None:
    log_lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    events = [parse_log_line(line) for line in log_lines if line.strip()]

    suspicious_ips = find_suspicious_ips(
        events,
        FAILED_LOGIN_THRESHOLD,
    )

    print(f"Loaded {len(events)} authentication events.")

    for ip_address, failed_attempts in suspicious_ips.items():
        print(
            f"ALERT: {ip_address} has "
            f"{failed_attempts} failed login attempts."
        )


if __name__ == "__main__":
    main()