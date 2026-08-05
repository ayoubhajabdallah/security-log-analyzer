import unittest

from fastapi.testclient import TestClient

from src.api import app


client = TestClient(app)


class TestSecurityLogAnalyzerApi(unittest.TestCase):
    def test_health_check(self) -> None:
        response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_analyzes_uploaded_log_file(self) -> None:
        log_content = (
            "2026-08-02T16:00:00Z,203.0.113.42,admin,FAILED\n"
            "2026-08-02T16:00:30Z,203.0.113.42,root,FAILED\n"
            "2026-08-02T16:01:00Z,203.0.113.42,admin,FAILED\n"
        )

        response = client.post(
            (
                "/analyze?"
                "failed_threshold=3&"
                "minimum_users=2&"
                "window_threshold=3&"
                "window_minutes=2"
            ),
            files={
                "file": (
                    "sample_auth.log",
                    log_content,
                    "text/plain",
                )
            },
        )

        self.assertEqual(response.status_code, 200)

        report = response.json()

        self.assertEqual(report["total_events"], 3)
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