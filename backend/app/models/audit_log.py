"""SentinelX Audit Log Model (SQLAlchemy 2.x)
"""

from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import String, Integer, DateTime, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.models.base import Base, utc_now


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(128), index=True, default="system")
    resource_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    __table_args__ = (
        Index("ix_audit_logs_action_timestamp", "action", "timestamp"),
    )
