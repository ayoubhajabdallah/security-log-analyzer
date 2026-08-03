from pathlib import Path

from src.analyzer import (
    find_ips_targeting_multiple_users,
    find_suspicious_ips,
)
from src.parser import load_events

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "data" / "sample_auth.log"
FAILED_LOGIN_THRESHOLD = 5
MINIMUM_TARGETED_USERS = 2




def main() -> None:
    events = load_events(LOG_FILE)

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