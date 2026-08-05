import unittest

from src.report import build_report


class TestBuildReport(unittest.TestCase):
    def test_builds_complete_security_report(self) -> None:
        events = [
            (
                "2026-08-02T16:00:00Z",
                "203.0.113.42",
                "admin",
                "FAILED",
            ),
            (
                "2026-08-02T16:00:30Z",
                "203.0.113.42",
                "root",
                "FAILED",
            ),
            (
                "2026-08-02T16:01:00Z",
                "203.0.113.42",
                "admin",
                "FAILED",
            ),
            (
                "2026-08-02T16:05:00Z",
                "192.0.2.10",
                "alice",
                "SUCCESS",
            ),
        ]

        report = build_report(
            events=events,
            failed_threshold=3,
            minimum_users=2,
            window_threshold=3,
            window_minutes=2,
        )

        self.assertEqual(report["total_events"], 4)
        self.assertEqual(
            report["suspicious_ips"],
            {"203.0.113.42": 3},
        )
        self.assertEqual(
            report["multi_user_ips"],
            {"203.0.113.42": ["admin", "root"]},
        )
        self.assertEqual(
            report["brute_force_ips"],
            {"203.0.113.42": 3},
        )


if __name__ == "__main__":
    unittest.main()