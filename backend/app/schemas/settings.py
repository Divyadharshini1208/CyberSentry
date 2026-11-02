"""SentinelX Settings & Audit Pydantic Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class SettingsUpdateRequest(BaseModel):
    settings: Dict[str, Any] = Field(..., description="Key-value user settings dictionary")


class SettingsResponse(BaseModel):
    clientIdentity: str
    settings: Dict[str, Any]
    updatedAt: datetime
    model_config = ConfigDict(from_attributes=True)


class AuditLogResponse(BaseModel):
    id: int
    action: str
    actor: str
    resourceType: str
    resourceId: Optional[str] = None
    details: Dict[str, Any]
    ipAddress: Optional[str] = None
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)
