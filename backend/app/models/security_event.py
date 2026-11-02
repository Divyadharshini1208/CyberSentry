"""SentinelX Security Event Model (SQLAlchemy 2.x)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import String, Integer, DateTime, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.models.base import Base, utc_now


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    risk_category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="Medium")
    detection_indicators: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    agent_dispatches: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(64), default="browser_extension")
    client_identity: Mapped[str] = mapped_column(String(128), index=True, default="default-client")
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("ix_security_events_domain_created", "domain", "created_at"),
        Index("ix_security_events_client_created", "client_identity", "created_at"),
    )
