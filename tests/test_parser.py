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

    def test_rejects_wrong_number_of_fields(self) -> None:
        line = "2026-08-02T16:02:14Z,203.0.113.42,FAILED"

        with self.assertRaises(ValueError):
            parse_log_line(line)

    def test_rejects_invalid_login_result(self) -> None:
        line = "2026-08-02T16:02:14Z,203.0.113.42,admin,UNKNOWN"

        with self.assertRaises(ValueError):
            parse_log_line(line)


if __name__ == "__main__":
    unittest.main()