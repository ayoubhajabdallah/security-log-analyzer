from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session, joinedload

from src.models import Analysis, BruteForceIP, MLAnomaly, MultiUserIP, SuspiciousIP


class AnalysisRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def save_analysis(
        self,
        filename: str,
        failed_threshold: int,
        minimum_users: int,
        window_threshold: int,
        window_minutes: int,
        report: Dict[str, Any],
    ) -> Analysis:
        analysis = Analysis(
            filename=filename,
            total_events=report.get("total_events", 0),
            failed_threshold=failed_threshold,
            minimum_users=minimum_users,
            window_threshold=window_threshold,
            window_minutes=window_minutes,
        )

        suspicious_ips = [
            SuspiciousIP(ip_address=ip, failed_attempts=count)
            for ip, count in report.get("suspicious_ips", {}).items()
        ]
        analysis.suspicious_ips.extend(suspicious_ips)

        multi_user_ips = [
            MultiUserIP(ip_address=ip, usernames=usernames)
            for ip, usernames in report.get("multi_user_ips", {}).items()
        ]
        analysis.multi_user_ips.extend(multi_user_ips)

        brute_force_ips = [
            BruteForceIP(ip_address=ip, failed_attempts=count)
            for ip, count in report.get("brute_force_ips", {}).items()
        ]
        analysis.brute_force_ips.extend(brute_force_ips)

        ml_anomalies = [
            MLAnomaly(
                ip_address=ip,
                anomaly_score=data["anomaly_score"],
                total_attempts=data["total_attempts"],
                failed_attempts=data["failed_attempts"],
                unique_users=data["unique_users"],
                failure_ratio=data["failure_ratio"],
            )
            for ip, data in report.get("ml_anomalies", {}).items()
        ]
        analysis.ml_anomalies.extend(ml_anomalies)

        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    def get_all_analyses(self) -> List[Analysis]:
        return (
            self.db.query(Analysis)
            .order_by(Analysis.timestamp.desc())
            .all()
        )

    def get_analysis_by_id(self, analysis_id: int) -> Optional[Analysis]:
        return (
            self.db.query(Analysis)
            .options(
                joinedload(Analysis.suspicious_ips),
                joinedload(Analysis.multi_user_ips),
                joinedload(Analysis.brute_force_ips),
                joinedload(Analysis.ml_anomalies),
            )
            .filter(Analysis.id == analysis_id)
            .first()
        )

    @staticmethod
    def to_dict(analysis: Analysis) -> Dict[str, Any]:
        return {
            "id": analysis.id,
            "filename": analysis.filename,
            "timestamp": analysis.timestamp.isoformat(),
            "total_events": analysis.total_events,
            "parameters": {
                "failed_threshold": analysis.failed_threshold,
                "minimum_users": analysis.minimum_users,
                "window_threshold": analysis.window_threshold,
                "window_minutes": analysis.window_minutes,
            },
            "suspicious_ips": {
                item.ip_address: item.failed_attempts
                for item in analysis.suspicious_ips
            },
            "multi_user_ips": {
                item.ip_address: item.usernames
                for item in analysis.multi_user_ips
            },
            "brute_force_ips": {
                item.ip_address: item.failed_attempts
                for item in analysis.brute_force_ips
            },
            "ml_anomalies": {
                item.ip_address: {
                    "anomaly_score": item.anomaly_score,
                    "total_attempts": item.total_attempts,
                    "failed_attempts": item.failed_attempts,
                    "unique_users": item.unique_users,
                    "failure_ratio": item.failure_ratio,
                }
                for item in analysis.ml_anomalies
            },
        }
