"""SentinelX Telemetry Service Tests
"""

from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.app.models.security_event import SecurityEvent
from backend.app.schemas.telemetry import SecurityEventCreate
from backend.app.services.telemetry_service import TelemetryService


@pytest.fixture
def mock_telemetry_service():
    session = AsyncMock()
    service = TelemetryService(session)
    service.repo = MagicMock()
    service.audit_repo = MagicMock()
    service.audit_repo.log_action = AsyncMock()
    return service


@pytest.mark.asyncio
async def test_ingest_and_retrieve_event(mock_telemetry_service: TelemetryService):
    now = datetime.now(timezone.utc)
    mock_event = SecurityEvent(
        event_id="evt_test_001",
        timestamp=now,
        domain="suspicious-bank-login.xyz",
        url="https://suspicious-bank-login.xyz/auth",
        risk_score=85,
        risk_category="Critical Risk",
        severity="critical",
        confidence="High",
        detection_indicators=[{
            "id": "BRAND_LOOKALIKE",
            "name": "Lookalike Brand Domain",
            "severity": "critical",
            "weight": 50,
            "description": "Mimics legitimate bank domain"
        }],
        agent_dispatches={},
        source="browser_extension",
        schema_version="1.0",
        client_identity="default-client",
        created_at=now
    )

    mock_telemetry_service.repo.create = AsyncMock(return_value=mock_event)
    mock_telemetry_service.repo.get_by_event_id = AsyncMock(return_value=mock_event)

    payload = SecurityEventCreate(
        eventId="evt_test_001",
        domain="suspicious-bank-login.xyz",
        url="https://suspicious-bank-login.xyz/auth",
        riskScore=85,
        riskCategory="Critical Risk",
        severity="critical",
        confidence="High",
        detectionIndicators=[{
            "id": "BRAND_LOOKALIKE",
            "name": "Lookalike Brand Domain",
            "severity": "critical",
            "weight": 50,
            "description": "Mimics legitimate bank domain"
        }],
        source="browser_extension",
        schemaVersion="1.0"
    )

    res = await mock_telemetry_service.ingest_event(payload, client_identity="client-123", ip_address="127.0.0.1")
    assert res.eventId == "evt_test_001"
    assert res.riskScore == 85
    assert res.domain == "suspicious-bank-login.xyz"
    assert len(res.detectionIndicators) == 1
    mock_telemetry_service.audit_repo.log_action.assert_awaited_once()

    retrieved = await mock_telemetry_service.get_event("evt_test_001")
    assert retrieved is not None
    assert retrieved.eventId == "evt_test_001"
