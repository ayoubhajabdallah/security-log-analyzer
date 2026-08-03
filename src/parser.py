from pathlib import Path

from src.analyzer import Event


def parse_log_line(line: str) -> Event:
    parts = [part.strip() for part in line.split(",")]

    if len(parts) != 4:
        raise ValueError(
            f"expected 4 fields, got {len(parts)}"
        )

    timestamp, ip_address, username, result = parts

    if result not in {"SUCCESS", "FAILED"}:
        raise ValueError(
            f"invalid login result: {result}"
        )

    return timestamp, ip_address, username, result


def load_events(log_file: Path) -> list[Event]:
    events: list[Event] = []

    for line_number, line in enumerate(
        log_file.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        try:
            event = parse_log_line(line)
        except ValueError as error:
            raise ValueError(
                f"line {line_number}: {error}"
            ) from error

        events.append(event)

    return events