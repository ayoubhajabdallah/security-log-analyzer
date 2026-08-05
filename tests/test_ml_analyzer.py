import unittest

from src.ml_analyzer import find_ml_anomalies


class TestMlAnomalyDetection(unittest.TestCase):
    def test_returns_empty_result_for_too_few_ips(self) -> None:
        events = [
            (
                "2026-08-02T16:00:00Z",
                "192.0.2.10",
                "alice",
                "SUCCESS",
            ),
            (
                "2026-08-02T16:01:00Z",
                "198.51.100.25",
                "bob",
                "FAILED",
            ),
        ]

        result = find_ml_anomalies(events)

        self.assertEqual(result, {})

    def test_detects_unusual_ip_behavior(self) -> None:
        events = []

        for index in range(20):
            events.append(
                (
                    f"2026-08-02T16:{index:02d}:00Z",
                    f"192.0.2.{index + 1}",
                    "normal-user",
                    "SUCCESS",
                )
            )

        suspicious_ip = "203.0.113.42"

        for index in range(20):
            events.append(
                (
                    f"2026-08-02T17:{index:02d}:00Z",
                    suspicious_ip,
                    f"user-{index % 10}",
                    "FAILED",
                )
            )

        result = find_ml_anomalies(events)

        self.assertIn(suspicious_ip, result)

        anomaly = result[suspicious_ip]

        self.assertEqual(anomaly["total_attempts"], 20)
        self.assertEqual(anomaly["failed_attempts"], 20)
        self.assertEqual(anomaly["unique_users"], 10)
        self.assertEqual(anomaly["failure_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()