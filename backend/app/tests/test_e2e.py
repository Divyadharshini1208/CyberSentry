"""SentinelX End-to-End System Tests
Tests the full lifecycle across all platform services and multi-agent workflows.
"""

from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.app.api.v1.health import health_check
from backend.app.core.config import settings
from backend.app.schemas.telemetry import SecurityEventCreate
from backend.app.schemas.scan import UrlScanRequest
from backend.app.models.security_event import SecurityEvent
from backend.app.services.telemetry_service import TelemetryService
from backend.app.services.scan_service import ScanService
from backend.app.agents.orchestrator import orchestrator
from backend.app.ml.model import url_classifier
from backend.app.intelligence.manager import threat_intel_manager


@pytest.mark.asyncio
async def test_full_platform_lifecycle():
    # 1. Health Verification
    health = await health_check()
    assert health["status"] == "healthy"
    assert health["service"] == settings.APP_NAME

    # 2. Threat Intel Provider Status
    ti_status = threat_intel_manager.get_providers_status()
    assert "virustotal" in ti_status
    assert "alienvault_otx" in ti_status
    assert "urlhaus" in ti_status

    # 3. Telemetry Ingestion Lifecycle
    now = datetime.now(timezone.utc)
    mock_session = AsyncMock()
    tel_service = TelemetryService(mock_session)
    tel_service.audit_repo = MagicMock()
    tel_service.audit_repo.log_action = AsyncMock()
    
    mock_event = SecurityEvent(
        event_id="evt_e2e_001",
        timestamp=now,
        domain="suspicious-bank-login.xyz",
        url="http://suspicious-bank-login.xyz/login.php",
        risk_score=75,
        risk_category="High Risk",
        severity="high",
        confidence="High",
        detection_indicators=[{"id": "INSECURE_HTTP", "name": "HTTP", "severity": "medium", "weight": 20}],
        agent_dispatches={},
        source="browser_extension",
        schema_version="1.0",
        client_identity="test-agent",
        created_at=now
    )
    tel_service.repo.create = AsyncMock(return_value=mock_event)

    tel_in = SecurityEventCreate(
        eventId="evt_e2e_001",
        domain="suspicious-bank-login.xyz",
        url="http://suspicious-bank-login.xyz/login.php",
        riskScore=75,
        riskCategory="High Risk",
        severity="high",
        confidence="High",
        detectionIndicators=[{"id": "INSECURE_HTTP", "name": "HTTP", "severity": "medium", "weight": 20}],
        source="browser_extension"
    )
    tel_res = await tel_service.ingest_event(tel_in, client_identity="test-agent", ip_address="127.0.0.1")
    assert tel_res.eventId == "evt_e2e_001"
    assert tel_res.riskScore == 75

    # 4. Deep URL Scan with Heuristics & ML
    scan_service = ScanService(mock_session)
    scan_service.repo.create = AsyncMock(side_effect=lambda s: s)
    scan_service.audit_repo.log_action = AsyncMock()

    scan_req = UrlScanRequest(
        url="https://paypa1-security-verify.xyz/account/login",
        enableThreatIntel=False,
        enableMl=True
    )
    scan_res = await scan_service.execute_scan(scan_req, ip_address="127.0.0.1")
    assert scan_res.riskScore >= 50
    assert scan_res.domain == "paypa1-security-verify.xyz"
    assert scan_res.mlPrediction.get("status") == "evaluated"

    # 5. Autonomous Multi-Agent Investigation
    inv_state = await orchestrator.run_investigation(
        investigation_id="inv_e2e_full_lifecycle",
        target_url="https://paypa1-security-verify.xyz/account/login",
        client_identity="e2e-tester"
    )
    assert inv_state.status == "completed"
    assert inv_state.finalRiskScore >= 50
    assert inv_state.finalCategory in ("High Risk", "Critical Risk")
    assert "URLIntelligenceAgent" in inv_state.agentResults
    assert "PhishingAnalysisAgent" in inv_state.agentResults
    assert "ThreatIntelligenceAgent" in inv_state.agentResults
    assert "RiskAssessmentAgent" in inv_state.agentResults
    assert "DigitalForensicsAgent" in inv_state.agentResults
    assert "ResponseAgent" in inv_state.agentResults
    assert "SecurityAuditorAgent" in inv_state.agentResults
    assert inv_state.auditedSuccessfully is True
    assert len(inv_state.evidenceTimeline) > 0
    assert "BLOCK" in inv_state.recommendedAction.upper() or "LEAVE" in inv_state.recommendedAction.upper()
