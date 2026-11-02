"""SentinelX URL Scan Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.schemas.common import APIResponse
from backend.app.schemas.scan import UrlScanRequest, UrlScanResponse
from backend.app.security.auth import verify_api_key
from backend.app.security.rate_limiter import check_rate_limit
from backend.app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["URL Scans"])


@router.post("/url", response_model=APIResponse[UrlScanResponse], status_code=status.HTTP_201_CREATED)
async def scan_url(
    req: UrlScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key),
    _rate: None = Depends(check_rate_limit)
):
    """Executes deterministic lexical scan, SSRF validation, threat intel lookups, and ML inference."""
    ip_addr = request.client.host if request.client else "unknown"
    service = ScanService(db)
    result = await service.execute_scan(req, ip_address=ip_addr)
    return APIResponse(success=True, message="URL scan completed", data=result)


@router.get("/{scan_id}", response_model=APIResponse[UrlScanResponse])
async def get_scan_result(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key)
):
    """Retrieves an existing scan result by scan ID."""
    service = ScanService(db)
    result = await service.get_scan_by_id(scan_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    return APIResponse(success=True, data=result)
