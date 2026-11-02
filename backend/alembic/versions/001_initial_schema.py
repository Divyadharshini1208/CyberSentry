"""Initial schema migration for SentinelX

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-01 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. security_events
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_category", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("detection_indicators", sa.JSON(), nullable=True),
        sa.Column("agent_dispatches", sa.JSON(), nullable=True),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("client_identity", sa.String(128), nullable=True),
        sa.Column("schema_version", sa.String(16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index("ix_security_events_event_id", "security_events", ["event_id"], unique=True)
    op.create_index("ix_security_events_domain", "security_events", ["domain"])
    op.create_index("ix_security_events_timestamp", "security_events", ["timestamp"])

    # 2. url_scans
    op.create_table(
        "url_scans",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_category", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("local_indicators", sa.JSON(), nullable=True),
        sa.Column("threat_intel_summary", sa.JSON(), nullable=True),
        sa.Column("ml_prediction", sa.JSON(), nullable=True),
        sa.Column("reasons", sa.JSON(), nullable=True),
        sa.Column("recommended_action", sa.String(255), nullable=True),
        sa.Column("client_identity", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index("ix_url_scans_scan_id", "url_scans", ["scan_id"], unique=True)
    op.create_index("ix_url_scans_domain", "url_scans", ["domain"])

    # 3. investigations
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("investigation_id", sa.String(64), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("orchestrator_summary", sa.Text(), nullable=True),
        sa.Column("agent_reports", sa.JSON(), nullable=True),
        sa.Column("final_risk_score", sa.Integer(), nullable=False),
        sa.Column("final_verdict", sa.String(64), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("evidence_timeline", sa.JSON(), nullable=True),
        sa.Column("recommended_action", sa.String(255), nullable=True),
        sa.Column("client_identity", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index("ix_investigations_id", "investigations", ["investigation_id"], unique=True)
    op.create_index("ix_investigations_domain", "investigations", ["domain"])

    # 4. agent_executions
    op.create_table(
        "agent_executions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("investigation_id", sa.String(64), nullable=False),
        sa.Column("agent_name", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("execution_time_ms", sa.Integer(), nullable=False),
        sa.Column("input_summary", sa.String(255), nullable=True),
        sa.Column("output_data", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index("ix_agent_executions_inv_id", "agent_executions", ["investigation_id"])

    # 5. audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])

    # 6. user_settings
    op.create_table(
        "user_settings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("client_identity", sa.String(128), nullable=False),
        sa.Column("settings_json", sa.JSON(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index("ix_user_settings_client", "user_settings", ["client_identity"], unique=True)

    # 7. threat_intel_cache
    op.create_table(
        "threat_intel_cache",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("indicator", sa.String(255), nullable=False),
        sa.Column("indicator_type", sa.String(32), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("is_malicious", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index("ix_threat_intel_cache_indicator", "threat_intel_cache", ["indicator"])


def downgrade() -> None:
    op.drop_table("threat_intel_cache")
    op.drop_table("user_settings")
    op.drop_table("audit_logs")
    op.drop_table("agent_executions")
    op.drop_table("investigations")
    op.drop_table("url_scans")
    op.drop_table("security_events")
