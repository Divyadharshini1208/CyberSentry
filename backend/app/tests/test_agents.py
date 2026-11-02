"""SentinelX Multi-Agent System Tests
"""

import pytest
from backend.app.agents.url_intelligence import URLIntelligenceAgent
from backend.app.agents.phishing_analysis import PhishingAnalysisAgent
from backend.app.agents.risk_assessment import RiskAssessmentAgent
from backend.app.agents.digital_forensics import DigitalForensicsAgent
from backend.app.agents.response_agent import ResponseAgent
from backend.app.agents.security_auditor import SecurityAuditorAgent
from backend.app.agents.orchestrator import orchestrator
from backend.app.agents.schemas import AgentEvidenceItem


@pytest.mark.asyncio
async def test_url_intelligence_agent():
    agent = URLIntelligenceAgent()
    res = await agent.execute("http://192.168.1.100/admin?id=123")
    assert res.status.value == "completed"
    assert any(e.id == "RAW_IP_HOSTNAME" for e in res.evidence)
    assert any(e.id == "INSECURE_HTTP_TRANSPORT" for e in res.evidence)


@pytest.mark.asyncio
async def test_phishing_analysis_agent():
    agent = PhishingAnalysisAgent()
    res = await agent.execute("https://paypa1-security-verify.xyz/login")
    assert res.status.value == "completed"
    assert res.data["impersonatedBrand"] == "paypal"
    assert any(e.id == "LOOKALIKE_BRAND_DOMAIN" for e in res.evidence)


@pytest.mark.asyncio
async def test_risk_assessment_agent():
    agent = RiskAssessmentAgent()
    evidence = [
        AgentEvidenceItem(
            id="CRITICAL_PHISH",
            sourceAgent="PhishingAnalysisAgent",
            category="phishing",
            description="Brand typosquatting detected",
            severity="critical",
            weight=50
        ),
        AgentEvidenceItem(
            id="RAW_IP",
            sourceAgent="URLIntelligenceAgent",
            category="url_structure",
            description="Raw IP host",
            severity="high",
            weight=30
        )
    ]
    res = await agent.execute(evidence)
    assert res.status.value == "completed"
    assert res.data["finalScore"] == 80
    assert res.data["category"] == "Critical Risk"


@pytest.mark.asyncio
async def test_forensics_and_response_agents():
    forensics = DigitalForensicsAgent()
    f_res = await forensics.execute("https://example.com", [])
    assert f_res.status.value == "completed"
    assert "urlSha256" in f_res.data
    assert len(f_res.data["timeline"]) >= 2

    response = ResponseAgent()
    r_res = await response.execute(score=85, category="Critical Risk", has_credential_risk=True)
    assert r_res.status.value == "completed"
    assert "BLOCK" in r_res.data["recommendation"]


@pytest.mark.asyncio
async def test_security_auditor_agent():
    auditor = SecurityAuditorAgent()
    evidence = [
        AgentEvidenceItem(
            id="TEST_EV",
            sourceAgent="URLIntelligenceAgent",
            category="url_structure",
            description="Test evidence",
            severity="moderate",
            weight=25
        )
    ]
    res = await auditor.execute(
        score=25,
        category="Moderate Risk",
        evidence=evidence,
        agent_results={}
    )
    assert res.status.value == "completed"
    assert res.data["isConsistent"] is True


@pytest.mark.asyncio
async def test_full_orchestrator_investigation():
    state = await orchestrator.run_investigation(
        investigation_id="inv_test_e2e_001",
        target_url="https://paypa1-security-verify.xyz/login",
        client_identity="test-client"
    )
    assert state.status == "completed"
    assert state.domain == "paypa1-security-verify.xyz"
    assert state.finalRiskScore >= 50
    assert state.finalCategory in ("High Risk", "Critical Risk")
    assert "URLIntelligenceAgent" in state.agentResults
    assert "PhishingAnalysisAgent" in state.agentResults
    assert "DigitalForensicsAgent" in state.agentResults
    assert len(state.evidenceTimeline) > 0
    assert state.auditedSuccessfully is True
