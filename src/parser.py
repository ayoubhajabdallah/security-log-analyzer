from pathlib import Path

from src.analyzer import Event


def parse_log_line(line: str) -> Event:
    parts = [part.strip() for part in line.split(",")]

    if len(parts) != 4:
        raise ValueError(
            f"Invalid log line: expected 4 fields, got {len(parts)}"
        )

    timestamp, ip_address, username, result = parts

    if result not in {"SUCCESS", "FAILED"}:
        raise ValueError(
            f"Invalid login result: {result}"
        )

    return timestamp, ip_address, username, result


def load_events(log_file: Path) -> list[Event]:
    log_lines = log_file.read_text(encoding="utf-8").splitlines()

    return [
        parse_log_line(line)
        for line in log_lines
        if line.strip()
    ]