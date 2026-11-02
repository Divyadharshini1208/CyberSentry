"""SentinelX Investigation Repository
"""

from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.investigation import Investigation, AgentExecution


class InvestigationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, inv: Investigation) -> Investigation:
        self.session.add(inv)
        await self.session.commit()
        await self.session.refresh(inv)
        return inv

    async def update(self, inv: Investigation) -> Investigation:
        await self.session.commit()
        await self.session.refresh(inv)
        return inv

    async def get_by_investigation_id(self, inv_id: str) -> Optional[Investigation]:
        query = select(Investigation).where(Investigation.investigation_id == inv_id)
        result = await self.session.execute(query)
        return result.scalars().first()

    async def record_agent_execution(self, exec_record: AgentExecution) -> AgentExecution:
        self.session.add(exec_record)
        await self.session.commit()
        await self.session.refresh(exec_record)
        return exec_record
