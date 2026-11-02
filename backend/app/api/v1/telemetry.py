"""SentinelX Telemetry Endpoints
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.schemas.common import APIResponse, PaginatedResponse
from backend.app.schemas.telemetry import SecurityEventCreate, SecurityEventResponse
from backend.app.security.auth import verify_api_key
from backend.app.security.rate_limiter import check_rate_limit
from backend.app.services.telemetry_service import TelemetryService

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("/events", response_model=APIResponse[SecurityEventResponse], status_code=status.HTTP_201_CREATED)
async def ingest_security_event(
    event_in: SecurityEventCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key),
    _rate: None = Depends(check_rate_limit)
):
    """Ingests, validates, and archives a client-side security event."""
    ip_addr = request.client.host if request.client else "unknown"
    service = TelemetryService(db)
    result = await service.ingest_event(event_in, client_identity="client-node", ip_address=ip_addr)
    return APIResponse(success=True, message="Security event ingested", data=result)


@router.get("/events", response_model=APIResponse[PaginatedResponse[SecurityEventResponse]])
async def list_security_events(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, moderate, high, critical)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key)
):
    """Retrieves paginated security event telemetry."""
    service = TelemetryService(db)
    offset = (page - 1) * page_size
    items, total = await service.list_events(domain=domain, severity=severity, limit=page_size, offset=offset)
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    paginated = PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )
    return APIResponse(success=True, data=paginated)


@router.get("/events/{event_id}", response_model=APIResponse[SecurityEventResponse])
async def get_security_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key)
):
    """Retrieves full details of a specific security event by event ID."""
    service = TelemetryService(db)
    event = await service.get_event(event_id)
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Event '{event_id}' not found")
    return APIResponse(success=True, data=event)
