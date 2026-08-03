from pathlib import Path

from src.analyzer import Event


def parse_log_line(line: str) -> Event:
    timestamp, ip_address, username, result = line.split(",")

    return timestamp, ip_address, username, result


def load_events(log_file: Path) -> list[Event]:
    log_lines = log_file.read_text(encoding="utf-8").splitlines()

    return [
        parse_log_line(line)
        for line in log_lines
        if line.strip()
    ]