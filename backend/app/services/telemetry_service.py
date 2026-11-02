"""SentinelX Telemetry Service
Handles ingestion, validation, and retrieval of client-reported security telemetry.
"""

from typing import List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.security_event import SecurityEvent
from backend.app.repositories.telemetry_repo import TelemetryRepository
from backend.app.repositories.audit_repo import AuditRepository
from backend.app.schemas.telemetry import SecurityEventCreate, SecurityEventResponse


class TelemetryService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = TelemetryRepository(session)
        self.audit_repo = AuditRepository(session)

    async def ingest_event(
        self,
        event_in: SecurityEventCreate,
        client_identity: str = "default-client",
        ip_address: str = "unknown"
    ) -> SecurityEventResponse:
        # Save event
        saved = await self.repo.create(event_in, client_identity=client_identity)

        # Audit if event is high or critical risk
        if saved.risk_score >= 50:
            await self.audit_repo.log_action(
                action="HIGH_RISK_EVENT_INGESTED",
                actor=client_identity,
                resource_type="security_event",
                resource_id=saved.event_id,
                details={
                    "domain": saved.domain,
                    "score": saved.risk_score,
                    "category": saved.risk_category,
                    "indicatorsCount": len(saved.detection_indicators)
                },
                ip_address=ip_address
            )

        return SecurityEventResponse(
            eventId=saved.event_id,
            timestamp=saved.timestamp,
            domain=saved.domain,
            url=saved.url,
            riskScore=saved.risk_score,
            riskCategory=saved.risk_category,
            severity=saved.severity,
            confidence=saved.confidence,
            detectionIndicators=saved.detection_indicators,
            agentDispatches=saved.agent_dispatches,
            source=saved.source,
            schemaVersion=saved.schema_version,
            clientIdentity=saved.client_identity,
            createdAt=saved.created_at
        )

    async def get_event(self, event_id: str) -> Optional[SecurityEventResponse]:
        event = await self.repo.get_by_event_id(event_id)
        if not event:
            return None
        return SecurityEventResponse(
            eventId=event.event_id,
            timestamp=event.timestamp,
            domain=event.domain,
            url=event.url,
            riskScore=event.risk_score,
            riskCategory=event.risk_category,
            severity=event.severity,
            confidence=event.confidence,
            detectionIndicators=event.detection_indicators,
            agentDispatches=event.agent_dispatches,
            source=event.source,
            schemaVersion=event.schema_version,
            clientIdentity=event.client_identity,
            createdAt=event.created_at
        )

    async def list_events(
        self,
        domain: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> Tuple[List[SecurityEventResponse], int]:
        events, total = await self.repo.list_events(domain=domain, severity=severity, limit=limit, offset=offset)
        items = [
            SecurityEventResponse(
                eventId=e.event_id,
                timestamp=e.timestamp,
                domain=e.domain,
                url=e.url,
                riskScore=e.risk_score,
                riskCategory=e.risk_category,
                severity=e.severity,
                confidence=e.confidence,
                detectionIndicators=e.detection_indicators,
                agentDispatches=e.agent_dispatches,
                source=e.source,
                schemaVersion=e.schema_version,
                clientIdentity=e.client_identity,
                createdAt=e.created_at
            )
            for e in events
        ]
        return items, total
