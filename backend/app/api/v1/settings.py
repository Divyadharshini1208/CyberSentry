"""SentinelX Settings & Policy Endpoints
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.repositories.audit_repo import SettingsRepository
from backend.app.schemas.common import APIResponse
from backend.app.schemas.settings import SettingsUpdateRequest, SettingsResponse
from backend.app.security.auth import verify_api_key

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("", response_model=APIResponse[SettingsResponse])
async def get_user_settings(
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key)
):
    """Retrieves user/client scoped settings."""
    repo = SettingsRepository(db)
    client_id = "default-client"
    setting = await repo.get_settings(client_id)
    if not setting:
        # Default policy
        default_data = {
            "protectionEnabled": True,
            "notificationsEnabled": True,
            "notificationThreshold": "high",
            "telemetryEnabled": True,
            "allowlist": ["google.com", "microsoft.com", "apple.com", "github.com"],
            "blocklist": []
        }
        setting = await repo.upsert_settings(client_id, default_data)

    return APIResponse(
        success=True,
        data=SettingsResponse(
            clientIdentity=setting.client_identity,
            settings=setting.settings_json,
            updatedAt=setting.updated_at
        )
    )


@router.put("", response_model=APIResponse[SettingsResponse])
async def update_user_settings(
    req: SettingsUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _auth: str = Depends(verify_api_key)
):
    """Updates user/client scoped settings."""
    repo = SettingsRepository(db)
    client_id = "default-client"
    updated = await repo.upsert_settings(client_id, req.settings)
    return APIResponse(
        success=True,
        message="Settings updated",
        data=SettingsResponse(
            clientIdentity=updated.client_identity,
            settings=updated.settings_json,
            updatedAt=updated.updated_at
        )
    )
