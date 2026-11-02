"""SentinelX Health & Readiness Endpoints
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.intelligence.manager import threat_intel_manager

router = APIRouter(tags=["Health"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Liveness probe returning application metadata and timestamp."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/ready", status_code=status.HTTP_200_OK)
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Readiness probe verifying database connectivity and threat intel adapter states."""
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {e}"

    ti_status = threat_intel_manager.get_providers_status()

    return {
        "status": "ready" if db_status == "connected" else "degraded",
        "database": db_status,
        "threatIntelProviders": ti_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
