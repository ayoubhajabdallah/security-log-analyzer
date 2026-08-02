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


if __name__ == "__main__":
    unittest.main()