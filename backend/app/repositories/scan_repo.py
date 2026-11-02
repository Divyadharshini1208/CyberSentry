"""SentinelX URL Scan Repository
"""

from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.url_scan import UrlScan


class ScanRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, scan: UrlScan) -> UrlScan:
        self.session.add(scan)
        await self.session.commit()
        await self.session.refresh(scan)
        return scan

    async def update(self, scan: UrlScan) -> UrlScan:
        await self.session.commit()
        await self.session.refresh(scan)
        return scan

    async def get_by_scan_id(self, scan_id: str) -> Optional[UrlScan]:
        query = select(UrlScan).where(UrlScan.scan_id == scan_id)
        result = await self.session.execute(query)
        return result.scalars().first()
