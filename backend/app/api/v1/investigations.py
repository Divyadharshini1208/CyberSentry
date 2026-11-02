"""SentinelX Multi-Agent Investigation Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.schemas.common import APIResponse
from backend.app.schemas.investigation import InvestigationRequest, InvestigationResponse
from backend.app.security.auth import verify_api_key
from backend.app.security.rate_limiter import check_rate_limit
from backend.app.services.investigation_service import InvestigationService

router = APIRouter(prefix="/investigations", tags=["Multi-Agent Investigations"])


@router.post("", response_model=APIResponse[InvestigationResponse], status_code=status.HTTP_201_CREATED)
async def create_investigation(
    req: InvestigationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key),
    _rate: None = Depends(check_rate_limit)
):
    """Initiates an autonomous 8-agent investigation workflow over the target URL."""
    ip_addr = request.client.host if request.client else "unknown"
    service = InvestigationService(db)
    result = await service.initiate_investigation(req, ip_address=ip_addr)
    return APIResponse(success=True, message="Investigation completed", data=result)


@router.get("/{investigation_id}", response_model=APIResponse[InvestigationResponse])
async def get_investigation_result(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key)
):
    """Retrieves full investigation findings, agent reports, and forensic timeline."""
    service = InvestigationService(db)
    result = await service.get_investigation_by_id(investigation_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found"
        )
    return APIResponse(success=True, data=result)
