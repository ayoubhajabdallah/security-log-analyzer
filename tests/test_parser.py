import unittest

from src.parser import parse_log_line


class TestParseLogLine(unittest.TestCase):
    def test_parses_valid_log_line(self) -> None:
        line = "2026-08-02T16:02:14Z,203.0.113.42,admin,FAILED"

        result = parse_log_line(line)

        self.assertEqual(
            result,
            (
                "2026-08-02T16:02:14Z",
                "203.0.113.42",
                "admin",
                "FAILED",
            ),
        )


if __name__ == "__main__":
    unittest.main()