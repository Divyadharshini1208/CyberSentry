"""SentinelX URL Scan Model (SQLAlchemy 2.x)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import String, Integer, DateTime, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.models.base import Base, utc_now


class UrlScan(Base):
    __tablename__ = "url_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_category: Mapped[str] = mapped_column(String(32), default="Low Risk")
    confidence: Mapped[str] = mapped_column(String(16), default="Medium")
    local_indicators: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    threat_intel_summary: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    ml_prediction: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    reasons: Mapped[List[str]] = mapped_column(JSON, default=list)
    recommended_action: Mapped[str] = mapped_column(String(255), default="Safe to browse")
    client_identity: Mapped[str] = mapped_column(String(128), index=True, default="default-client")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_url_scans_domain_created", "domain", "created_at"),
    )
