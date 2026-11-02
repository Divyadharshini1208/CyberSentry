"""SentinelX Telemetry Repository
Data access layer for SecurityEvent models using SQLAlchemy 2.x async session.
"""

from typing import List, Optional, Tuple
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.security_event import SecurityEvent
from backend.app.schemas.telemetry import SecurityEventCreate


class TelemetryRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event_in: SecurityEventCreate, client_identity: str = "default-client") -> SecurityEvent:
        event = SecurityEvent(
            event_id=event_in.eventId or f"evt_{int(event_in.timestamp.timestamp()*1000)}",
            timestamp=event_in.timestamp,
            domain=event_in.domain,
            url=event_in.url,
            risk_score=event_in.riskScore,
            risk_category=event_in.riskCategory,
            severity=event_in.severity,
            confidence=event_in.confidence or "Medium",
            detection_indicators=[i.model_dump() for i in event_in.detectionIndicators],
            agent_dispatches=event_in.agentDispatches or {},
            source=event_in.source or "browser_extension",
            client_identity=client_identity,
            schema_version=event_in.schemaVersion or "1.0"
        )
        self.session.add(event)
        await self.session.commit()
        await self.session.refresh(event)
        return event

    async def get_by_event_id(self, event_id: str) -> Optional[SecurityEvent]:
        query = select(SecurityEvent).where(SecurityEvent.event_id == event_id)
        result = await self.session.execute(query)
        return result.scalars().first()

    async def list_events(
        self,
        domain: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> Tuple[List[SecurityEvent], int]:
        query = select(SecurityEvent)
        count_query = select(func.count(SecurityEvent.id))

        if domain:
            query = query.where(SecurityEvent.domain.ilike(f"%{domain}%"))
            count_query = count_query.where(SecurityEvent.domain.ilike(f"%{domain}%"))

        if severity:
            query = query.where(SecurityEvent.severity == severity.lower())
            count_query = count_query.where(SecurityEvent.severity == severity.lower())

        total = await self.session.scalar(count_query) or 0

        query = query.order_by(desc(SecurityEvent.created_at)).limit(limit).offset(offset)
        result = await self.session.execute(query)
        events = list(result.scalars().all())

        return events, total
