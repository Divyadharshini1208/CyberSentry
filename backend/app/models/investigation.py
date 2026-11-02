"""SentinelX Investigation Model (SQLAlchemy 2.x)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import String, Integer, DateTime, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.models.base import Base, utc_now


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    orchestrator_summary: Mapped[str] = mapped_column(Text, default="")
    agent_reports: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    final_risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    final_verdict: Mapped[str] = mapped_column(String(64), default="Inconclusive")
    confidence: Mapped[str] = mapped_column(String(16), default="Medium")
    evidence_timeline: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    recommended_action: Mapped[str] = mapped_column(String(255), default="Continue monitoring")
    client_identity: Mapped[str] = mapped_column(String(128), index=True, default="default-client")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentExecution(Base):
    __tablename__ = "agent_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    agent_name: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)  # pending, running, completed, failed, skipped
    execution_time_ms: Mapped[int] = mapped_column(Integer, default=0)
    input_summary: Mapped[str] = mapped_column(String(255), default="")
    output_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
