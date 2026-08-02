import unittest

from src.analyzer import find_suspicious_ips


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

if __name__ == "__main__":
    unittest.main()