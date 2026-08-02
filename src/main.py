from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "data" / "sample_auth.log"


def main() -> None:
    log_lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    print(f"Loaded {len(log_lines)} authentication events.")


if __name__ == "__main__":
    main()