"""SentinelX Audit Endpoints
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.repositories.audit_repo import AuditRepository
from backend.app.schemas.common import APIResponse, PaginatedResponse
from backend.app.schemas.settings import AuditLogResponse
from backend.app.security.auth import verify_api_key

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("", response_model=APIResponse[PaginatedResponse[AuditLogResponse]])
async def get_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key)
):
    """Retrieves paginated audit log trail."""
    repo = AuditRepository(db)
    offset = (page - 1) * page_size
    logs, total = await repo.list_logs(limit=page_size, offset=offset)
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    items = [
        AuditLogResponse(
            id=log.id,
            action=log.action,
            actor=log.actor,
            resourceType=log.resource_type,
            resourceId=log.resource_id,
            details=log.details,
            ipAddress=log.ip_address,
            timestamp=log.timestamp
        )
        for log in logs
    ]

    paginated = PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )
    return APIResponse(success=True, data=paginated)
