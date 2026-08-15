from datetime import datetime, timezone
from typing import Any, List

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    total_events: Mapped[int] = mapped_column(Integer, nullable=False)
    failed_threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    minimum_users: Mapped[int] = mapped_column(Integer, nullable=False)
    window_threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)

    suspicious_ips: Mapped[List["SuspiciousIP"]] = relationship(
        "SuspiciousIP", back_populates="analysis", cascade="all, delete-orphan"
    )
    multi_user_ips: Mapped[List["MultiUserIP"]] = relationship(
        "MultiUserIP", back_populates="analysis", cascade="all, delete-orphan"
    )
    brute_force_ips: Mapped[List["BruteForceIP"]] = relationship(
        "BruteForceIP", back_populates="analysis", cascade="all, delete-orphan"
    )
    ml_anomalies: Mapped[List["MLAnomaly"]] = relationship(
        "MLAnomaly", back_populates="analysis", cascade="all, delete-orphan"
    )


class SuspiciousIP(Base):
    __tablename__ = "suspicious_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False)

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="suspicious_ips")


class MultiUserIP(Base):
    __tablename__ = "multi_user_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    usernames: Mapped[Any] = mapped_column(JSON, nullable=False)

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="multi_user_ips")


class BruteForceIP(Base):
    __tablename__ = "brute_force_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False)

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="brute_force_ips")


class MLAnomaly(Base):
    __tablename__ = "ml_anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    total_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    unique_users: Mapped[int] = mapped_column(Integer, nullable=False)
    failure_ratio: Mapped[float] = mapped_column(Float, nullable=False)

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="ml_anomalies")
