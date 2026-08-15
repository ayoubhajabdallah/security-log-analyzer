import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api import app
from src.database import Base, engine as prod_engine, get_db
from src.repository import AnalysisRepository


TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


class TestPersistenceLayer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls) -> None:
        app.dependency_overrides.clear()

    def setUp(self) -> None:
        Base.metadata.create_all(bind=test_engine)
        Base.metadata.create_all(bind=prod_engine)
        self.db = TestingSessionLocal()

    def tearDown(self) -> None:
        self.db.close()
        Base.metadata.drop_all(bind=test_engine)
        Base.metadata.create_all(bind=prod_engine)

    def test_repository_save_and_retrieve_analysis(self) -> None:
        repo = AnalysisRepository(self.db)
        sample_report = {
            "total_events": 10,
            "suspicious_ips": {"192.168.1.1": 6},
            "multi_user_ips": {"192.168.1.1": ["user1", "user2"]},
            "brute_force_ips": {"192.168.1.1": 4},
            "ml_anomalies": {
                "192.168.1.1": {
                    "anomaly_score": 0.85,
                    "total_attempts": 10,
                    "failed_attempts": 6,
                    "unique_users": 2,
                    "failure_ratio": 0.6,
                }
            },
        }

        analysis = repo.save_analysis(
            filename="test_auth.log",
            failed_threshold=5,
            minimum_users=2,
            window_threshold=3,
            window_minutes=2,
            report=sample_report,
        )

        self.assertIsNotNone(analysis.id)
        self.assertEqual(analysis.filename, "test_auth.log")
        self.assertEqual(analysis.total_events, 10)

        fetched = repo.get_analysis_by_id(analysis.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.filename, "test_auth.log")

        dict_format = repo.to_dict(fetched)
        self.assertEqual(dict_format["id"], analysis.id)
        self.assertEqual(dict_format["suspicious_ips"], {"192.168.1.1": 6})
        self.assertEqual(
            dict_format["multi_user_ips"], {"192.168.1.1": ["user1", "user2"]}
        )
        self.assertEqual(
            dict_format["ml_anomalies"]["192.168.1.1"]["anomaly_score"], 0.85
        )

    def test_api_list_and_get_analyses(self) -> None:
        log_content = (
            "2026-08-02T16:00:00Z,203.0.113.42,admin,FAILED\n"
            "2026-08-02T16:00:30Z,203.0.113.42,root,FAILED\n"
            "2026-08-02T16:01:00Z,203.0.113.42,admin,FAILED\n"
        )

        post_res = self.client.post(
            "/analyze?failed_threshold=3&minimum_users=2&window_threshold=3&window_minutes=2",
            files={"file": ("sample_auth.log", log_content, "text/plain")},
        )
        self.assertEqual(post_res.status_code, 200)

        list_res = self.client.get("/analyses")
        self.assertEqual(list_res.status_code, 200)
        analyses = list_res.json()
        self.assertGreaterEqual(len(analyses), 1)

        analysis_id = analyses[0]["id"]
        detail_res = self.client.get(f"/analyses/{analysis_id}")
        self.assertEqual(detail_res.status_code, 200)
        detail = detail_res.json()

        self.assertEqual(detail["id"], analysis_id)
        self.assertEqual(detail["filename"], "sample_auth.log")
        self.assertIn("203.0.113.42", detail["suspicious_ips"])

    def test_get_nonexistent_analysis_returns_404(self) -> None:
        response = self.client.get("/analyses/99999")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
