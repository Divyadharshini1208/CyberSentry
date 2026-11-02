"""SentinelX User Settings and Threat Intel Cache Models (SQLAlchemy 2.x)
"""

from datetime import datetime
from typing import Any, Dict
from sqlalchemy import String, Integer, DateTime, JSON, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.models.base import Base, utc_now


class UserSetting(Base):
    __tablename__ = "user_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_identity: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    settings_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # domain, url, ip
    provider: Mapped[str] = mapped_column(String(64), index=True, nullable=False)        # virustotal, alienvault, urlhaus
    result_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("ix_threat_cache_lookup", "indicator", "provider"),
    )
