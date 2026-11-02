"""SentinelX Audit & Settings Repositories
"""

from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.audit_log import AuditLog
from backend.app.models.user_setting import UserSetting


class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def log_action(
        self,
        action: str,
        actor: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> AuditLog:
        entry = AuditLog(
            action=action,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address
        )
        self.session.add(entry)
        await self.session.commit()
        await self.session.refresh(entry)
        return entry

    async def list_logs(self, limit: int = 20, offset: int = 0) -> Tuple[List[AuditLog], int]:
        total = await self.session.scalar(select(func.count(AuditLog.id))) or 0
        query = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit).offset(offset)
        result = await self.session.execute(query)
        return list(result.scalars().all()), total


class SettingsRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_settings(self, client_identity: str) -> Optional[UserSetting]:
        query = select(UserSetting).where(UserSetting.client_identity == client_identity)
        result = await self.session.execute(query)
        return result.scalars().first()

    async def upsert_settings(self, client_identity: str, settings_data: Dict[str, Any]) -> UserSetting:
        existing = await self.get_settings(client_identity)
        if existing:
            existing.settings_json = settings_data
            await self.session.commit()
            await self.session.refresh(existing)
            return existing
        else:
            new_setting = UserSetting(
                client_identity=client_identity,
                settings_json=settings_data
            )
            self.session.add(new_setting)
            await self.session.commit()
            await self.session.refresh(new_setting)
            return new_setting
