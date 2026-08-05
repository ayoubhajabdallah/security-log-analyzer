from collections import defaultdict
from typing import TypedDict

from sklearn.ensemble import IsolationForest

from src.analyzer import Event


class AnomalyResult(TypedDict):
    anomaly_score: float
    total_attempts: int
    failed_attempts: int
    unique_users: int
    failure_ratio: float


def find_ml_anomalies(
    events: list[Event],
) -> dict[str, AnomalyResult]:
    statistics: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "total_attempts": 0,
            "failed_attempts": 0,
            "usernames": set(),
        }
    )

    for _, ip_address, username, result in events:
        ip_statistics = statistics[ip_address]

        ip_statistics["total_attempts"] = (
            int(ip_statistics["total_attempts"]) + 1
        )

        if result == "FAILED":
            ip_statistics["failed_attempts"] = (
                int(ip_statistics["failed_attempts"]) + 1
            )

        usernames = ip_statistics["usernames"]

        if isinstance(usernames, set):
            usernames.add(username)

    ip_addresses = sorted(statistics)

    if len(ip_addresses) < 3:
        return {}

    feature_matrix: list[list[float]] = []

    for ip_address in ip_addresses:
        ip_statistics = statistics[ip_address]

        total_attempts = int(
            ip_statistics["total_attempts"]
        )
        failed_attempts = int(
            ip_statistics["failed_attempts"]
        )
        usernames = ip_statistics["usernames"]

        unique_users = (
            len(usernames)
            if isinstance(usernames, set)
            else 0
        )

        failure_ratio = (
            failed_attempts / total_attempts
            if total_attempts
            else 0.0
        )

        feature_matrix.append(
            [
                float(total_attempts),
                float(failed_attempts),
                float(unique_users),
                failure_ratio,
            ]
        )

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )

    predictions = model.fit_predict(feature_matrix)
    anomaly_scores = -model.score_samples(feature_matrix)

    anomalies: dict[str, AnomalyResult] = {}

    for index, prediction in enumerate(predictions):
        if prediction != -1:
            continue

        ip_address = ip_addresses[index]
        ip_statistics = statistics[ip_address]

        total_attempts = int(
            ip_statistics["total_attempts"]
        )
        failed_attempts = int(
            ip_statistics["failed_attempts"]
        )
        usernames = ip_statistics["usernames"]

        unique_users = (
            len(usernames)
            if isinstance(usernames, set)
            else 0
        )

        failure_ratio = (
            failed_attempts / total_attempts
            if total_attempts
            else 0.0
        )

        anomalies[ip_address] = {
            "anomaly_score": round(
                float(anomaly_scores[index]),
                4,
            ),
            "total_attempts": total_attempts,
            "failed_attempts": failed_attempts,
            "unique_users": unique_users,
            "failure_ratio": round(failure_ratio, 4),
        }

    return anomalies