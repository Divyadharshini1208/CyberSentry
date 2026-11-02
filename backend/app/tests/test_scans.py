"""SentinelX URL Scan Service Tests
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.app.core.exceptions import SSRFViolationError
from backend.app.schemas.scan import UrlScanRequest
from backend.app.services.scan_service import ScanService


@pytest.fixture
def mock_scan_service():
    session = AsyncMock()
    service = ScanService(session)
    service.repo = MagicMock()
    service.repo.create = AsyncMock(side_effect=lambda scan: scan)
    service.audit_repo = MagicMock()
    service.audit_repo.log_action = AsyncMock()
    return service


@pytest.mark.asyncio
async def test_scan_safe_url(mock_scan_service: ScanService):
    req = UrlScanRequest(
        url="https://github.com/torvalds/linux",
        enableThreatIntel=False,
        enableMl=True
    )
    res = await mock_scan_service.execute_scan(req, ip_address="127.0.0.1")
    assert res.domain == "github.com"
    assert res.riskCategory in ("Low Risk", "Moderate Risk")
    assert res.scanId.startswith("scn_")
    assert res.severity in ("low", "moderate")


@pytest.mark.asyncio
async def test_scan_phishing_lookalike(mock_scan_service: ScanService):
    req = UrlScanRequest(
        url="https://paypa1-security-verify.xyz/login",
        enableThreatIntel=False,
        enableMl=True
    )
    res = await mock_scan_service.execute_scan(req, ip_address="127.0.0.1")
    assert res.riskScore >= 50
    assert res.riskCategory in ("High Risk", "Critical Risk")
    assert any("paypal" in r.lower() or "lookalike" in r.lower() or "xyz" in r.lower() for r in res.reasons)


@pytest.mark.asyncio
async def test_scan_ssrf_blocked(mock_scan_service: ScanService):
    req = UrlScanRequest(
        url="http://127.0.0.1:8000/private",
        enableThreatIntel=False
    )
    with pytest.raises(SSRFViolationError):
        await mock_scan_service.execute_scan(req, ip_address="127.0.0.1")
