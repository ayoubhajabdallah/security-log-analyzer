from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "data" / "sample_auth.log"
FAILED_LOGIN_THRESHOLD = 5


def parse_log_line(line: str) -> tuple[str, str, str, str]:
    timestamp, ip_address, username, result = line.split(",")
    return timestamp, ip_address, username, result


def main() -> None:
    log_lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    events = [parse_log_line(line) for line in log_lines if line.strip()]

    failed_attempts_by_ip = Counter(
        ip_address
        for _, ip_address, _, result in events
        if result == "FAILED"
    )

    print(f"Loaded {len(events)} authentication events.")

    for ip_address, failed_attempts in failed_attempts_by_ip.items():
        if failed_attempts >= FAILED_LOGIN_THRESHOLD:
            print(
                f"ALERT: {ip_address} has "
                f"{failed_attempts} failed login attempts."
            )


if __name__ == "__main__":
    main()