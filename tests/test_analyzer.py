import unittest

from src.analyzer import (
    find_ips_targeting_multiple_users,
    find_suspicious_ips,
)


class TestFindSuspiciousIps(unittest.TestCase):
    def test_detects_ip_reaching_threshold(self) -> None:
        events = [
            ("time1", "203.0.113.42", "admin", "FAILED"),
            ("time2", "203.0.113.42", "admin", "FAILED"),
            ("time3", "203.0.113.42", "root", "FAILED"),
        ]

        result = find_suspicious_ips(events, threshold=3)

        self.assertEqual(result, {"203.0.113.42": 3})

    def test_ignores_ip_below_threshold(self) -> None:
        events = [
            ("time1", "198.51.100.88", "charlie", "FAILED"),
            ("time2", "198.51.100.88", "charlie", "FAILED"),
            ("time3", "198.51.100.88", "charlie", "SUCCESS"),
        ]

        result = find_suspicious_ips(events, threshold=3)

        self.assertEqual(result, {})
    def test_detects_ip_targeting_multiple_users(self) -> None:
        events = [
            ("time1", "203.0.113.42", "admin", "FAILED"),
            ("time2", "203.0.113.42", "root", "FAILED"),
            ("time3", "203.0.113.42", "admin", "FAILED"),
            ("time4", "198.51.100.88", "charlie", "FAILED"),
        ]

        result = find_ips_targeting_multiple_users(
        events,
        minimum_users=2,
    )

        self.assertEqual(
            result,
            {"203.0.113.42": {"admin", "root"}},
    )

if __name__ == "__main__":
    unittest.main()