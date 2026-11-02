"""SentinelX API v1 Package
"""

from fastapi import APIRouter
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.telemetry import router as telemetry_router
from backend.app.api.v1.scans import router as scans_router
from backend.app.api.v1.investigations import router as investigations_router
from backend.app.api.v1.settings import router as settings_router
from backend.app.api.v1.audit import router as audit_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(telemetry_router)
api_v1_router.include_router(scans_router)
api_v1_router.include_router(investigations_router)
api_v1_router.include_router(settings_router)
api_v1_router.include_router(audit_router)
