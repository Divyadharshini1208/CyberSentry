"""SentinelX Investigation Service
Manages initiation, execution, and persistence of multi-agent investigations.
"""

import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.investigation import Investigation, AgentExecution
from backend.app.repositories.investigation_repo import InvestigationRepository
from backend.app.repositories.audit_repo import AuditRepository
from backend.app.schemas.investigation import InvestigationRequest, InvestigationResponse
from backend.app.security.ssrf_guard import validate_url_for_outbound
from backend.app.agents.orchestrator import orchestrator


class InvestigationService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = InvestigationRepository(session)
        self.audit_repo = AuditRepository(session)

    async def initiate_investigation(
        self,
        req: InvestigationRequest,
        ip_address: str = "unknown"
    ) -> InvestigationResponse:
        # Validate SSRF
        validate_url_for_outbound(req.url)

        inv_id = f"inv_{uuid.uuid4().hex[:12]}"
        client_id = req.clientIdentity or "default-client"

        # Execute investigation workflow through Orchestrator
        state = await orchestrator.run_investigation(
            investigation_id=inv_id,
            target_url=req.url,
            scan_id=req.scanId,
            client_identity=client_id
        )

        # Persist Investigation to DB
        inv_record = Investigation(
            investigation_id=inv_id,
            scan_id=req.scanId,
            target_url=req.url,
            domain=state.domain,
            status=state.status,
            orchestrator_summary=state.orchestratorSummary,
            agent_reports={k: v.model_dump() for k, v in state.agentResults.items()},
            final_risk_score=state.finalRiskScore,
            final_verdict=state.finalVerdict,
            confidence=state.confidence,
            evidence_timeline=state.evidenceTimeline,
            recommended_action=state.recommendedAction,
            client_identity=client_id,
            completed_at=state.completedAt
        )
        saved = await self.repo.create(inv_record)

        # Persist individual AgentExecution records
        for agent_name, res in state.agentResults.items():
            exec_record = AgentExecution(
                investigation_id=inv_id,
                agent_name=agent_name,
                status=res.status.value,
                execution_time_ms=res.executionTimeMs,
                input_summary=req.url[:250],
                output_data=res.data,
                error_message=res.errorMessage
            )
            await self.repo.record_agent_execution(exec_record)

        # Audit log
        await self.audit_repo.log_action(
            action="MULTI_AGENT_INVESTIGATION",
            actor=client_id,
            resource_type="investigation",
            resource_id=inv_id,
            details={
                "url": req.url,
                "domain": state.domain,
                "score": state.finalRiskScore,
                "verdict": state.finalVerdict,
                "agentsCount": len(state.agentResults)
            },
            ip_address=ip_address
        )

        return InvestigationResponse(
            investigationId=saved.investigation_id,
            scanId=saved.scan_id,
            targetUrl=saved.target_url,
            domain=saved.domain,
            status=saved.status,
            finalRiskScore=saved.final_risk_score,
            finalVerdict=saved.final_verdict,
            confidence=saved.confidence,
            recommendedAction=saved.recommended_action,
            orchestratorSummary=saved.orchestrator_summary,
            agentReports=saved.agent_reports,
            evidenceTimeline=saved.evidence_timeline,
            createdAt=saved.created_at,
            completedAt=saved.completed_at
        )

    async def get_investigation_by_id(self, inv_id: str) -> Optional[InvestigationResponse]:
        inv = await self.repo.get_by_investigation_id(inv_id)
        if not inv:
            return None

        return InvestigationResponse(
            investigationId=inv.investigation_id,
            scanId=inv.scan_id,
            targetUrl=inv.target_url,
            domain=inv.domain,
            status=inv.status,
            finalRiskScore=inv.final_risk_score,
            finalVerdict=inv.final_verdict,
            confidence=inv.confidence,
            recommendedAction=inv.recommended_action,
            orchestratorSummary=inv.orchestrator_summary,
            agentReports=inv.agent_reports,
            evidenceTimeline=inv.evidence_timeline,
            createdAt=inv.created_at,
            completedAt=inv.completed_at
        )
