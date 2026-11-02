"""SentinelX Orchestrator Agent & Investigation Workflow
Orchestrates the 8-agent security investigation state machine with bounded execution and error recovery.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.agents.schemas import InvestigationState, AgentStatus
from backend.app.agents.url_intelligence import URLIntelligenceAgent
from backend.app.agents.phishing_analysis import PhishingAnalysisAgent
from backend.app.agents.threat_intelligence import ThreatIntelligenceAgent
from backend.app.agents.risk_assessment import RiskAssessmentAgent
from backend.app.agents.digital_forensics import DigitalForensicsAgent
from backend.app.agents.response_agent import ResponseAgent
from backend.app.agents.security_auditor import SecurityAuditorAgent


class OrchestratorAgent:
    def __init__(self):
        self.url_agent = URLIntelligenceAgent()
        self.phishing_agent = PhishingAnalysisAgent()
        self.ti_agent = ThreatIntelligenceAgent()
        self.risk_agent = RiskAssessmentAgent()
        self.forensics_agent = DigitalForensicsAgent()
        self.response_agent = ResponseAgent()
        self.auditor_agent = SecurityAuditorAgent()

    async def run_investigation(
        self,
        investigation_id: str,
        target_url: str,
        scan_id: Optional[str] = None,
        client_identity: str = "default-client"
    ) -> InvestigationState:
        """Executes the full multi-agent investigation workflow within bounded timeouts."""
        domain = urlparse(target_url).netloc.split(":")[0].lower()

        state = InvestigationState(
            investigationId=investigation_id,
            targetUrl=target_url,
            domain=domain,
            scanId=scan_id,
            clientIdentity=client_identity,
            status="in_progress"
        )

        all_evidence = []

        try:
            # Phase 1: URL, Phishing, and Threat Intelligence Agent execution
            url_res = await self.url_agent.execute(target_url)
            state.agentResults[url_res.agentName] = url_res
            all_evidence.extend(url_res.evidence)

            phish_res = await self.phishing_agent.execute(target_url)
            state.agentResults[phish_res.agentName] = phish_res
            all_evidence.extend(phish_res.evidence)

            ti_res = await self.ti_agent.execute(target_url)
            state.agentResults[ti_res.agentName] = ti_res
            all_evidence.extend(ti_res.evidence)

            # Phase 2: Risk Assessment synthesis
            risk_result = await self.risk_agent.execute(all_evidence)
            state.agentResults[risk_result.agentName] = risk_result
            final_score = risk_result.data.get("finalScore", 0)
            final_category = risk_result.data.get("category", "Low Risk")
            final_verdict = risk_result.data.get("verdict", "Inconclusive")
            confidence = risk_result.data.get("confidence", "Medium")

            state.finalRiskScore = final_score
            state.finalCategory = final_category
            state.finalVerdict = final_verdict
            state.confidence = confidence

            # Phase 3: Digital Forensics timeline & hash sealing
            forensics_result = await self.forensics_agent.execute(target_url, all_evidence)
            state.agentResults[forensics_result.agentName] = forensics_result
            state.evidenceTimeline = forensics_result.data.get("timeline", [])

            # Phase 4: Defensive Response recommendation
            has_credential_risk = any(e.category == "phishing" for e in all_evidence)
            response_result = await self.response_agent.execute(final_score, final_category, has_credential_risk)
            state.agentResults[response_result.agentName] = response_result
            state.recommendedAction = response_result.data.get("recommendation", "Safe to browse")

            # Phase 5: Security Auditor verification
            audit_result = await self.auditor_agent.execute(final_score, final_category, all_evidence, state.agentResults)
            state.agentResults[audit_result.agentName] = audit_result
            state.auditedSuccessfully = audit_result.data.get("isConsistent", False)
            state.auditWarnings = audit_result.data.get("warnings", [])

            # Phase 6: Orchestrator Executive Summary
            state.status = "completed"
            state.completedAt = datetime.now(timezone.utc)
            state.orchestratorSummary = (
                f"Investigation complete for {domain}. Assessed Risk: {final_score}/100 ({final_category}). "
                f"Evidence: {len(all_evidence)} verified indicators. Verdict: {final_verdict}. "
                f"Audit Status: {'Verified' if state.auditedSuccessfully else 'Warnings Flagged'}."
            )

        except Exception as e:
            logger.error(f"[Orchestrator] Fatal investigation error: {e}")
            state.status = "failed"
            state.completedAt = datetime.now(timezone.utc)
            state.orchestratorSummary = f"Investigation aborted due to error: {e}"

        return state


orchestrator = OrchestratorAgent()
