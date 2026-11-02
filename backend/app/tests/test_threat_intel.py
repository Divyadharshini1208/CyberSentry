"""SentinelX Threat Intelligence Tests
"""

import pytest
from backend.app.intelligence.virustotal import VirusTotalAdapter
from backend.app.intelligence.alienvault import AlienVaultOTXAdapter
from backend.app.intelligence.urlhaus import URLhausAdapter
from backend.app.intelligence.manager import ThreatIntelManager


@pytest.mark.asyncio
async def test_virustotal_unconfigured():
    vt = VirusTotalAdapter(api_key=None)
    assert not vt.is_configured
    res = await vt.lookup_domain("example.com")
    assert res.status == "unconfigured"
    assert not res.is_malicious


@pytest.mark.asyncio
async def test_alienvault_unconfigured():
    otx = AlienVaultOTXAdapter(api_key=None)
    assert not otx.is_configured
    res = await otx.lookup_domain("example.com")
    assert res.status == "unconfigured"
    assert not res.is_malicious


@pytest.mark.asyncio
async def test_threat_intel_manager_synthesis():
    manager = ThreatIntelManager()
    status = manager.get_providers_status()
    assert "virustotal" in status
    assert "alienvault_otx" in status
    assert "urlhaus" in status
