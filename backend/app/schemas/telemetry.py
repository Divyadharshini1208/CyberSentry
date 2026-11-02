"""SentinelX Telemetry Pydantic Schemas
Validates incoming security events from browser extensions and mobile sentinels.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class IndicatorSchema(BaseModel):
    id: str = Field(..., max_length=64)
    name: str = Field(..., max_length=128)
    severity: str = Field(default="moderate", max_length=32)
    weight: int = Field(default=0, ge=0, le=100)
    scoreContribution: Optional[int] = Field(default=0)
    description: Optional[str] = Field(default=None)
    category: Optional[str] = Field(default="general")


class SecurityEventCreate(BaseModel):
    eventId: Optional[str] = Field(default=None, max_length=64, description="Optional client event ID")
    timestamp: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    domain: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1, max_length=4096)
    riskScore: int = Field(..., ge=0, le=100)
    riskCategory: str = Field(..., max_length=32)
    severity: str = Field(default="low", max_length=16)
    confidence: Optional[str] = Field(default="Medium", max_length=16)
    detectionIndicators: List[IndicatorSchema] = Field(default_factory=list)
    agentDispatches: Optional[Dict[str, Any]] = Field(default_factory=dict)
    source: Optional[str] = Field(default="browser_extension", max_length=64)
    schemaVersion: Optional[str] = Field(default="1.0", max_length=16)

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean.startswith("http://") or clean.startswith("https://"):
            from urllib.parse import urlparse
            clean = urlparse(clean).netloc
        return clean.split(":")[0]


class SecurityEventResponse(BaseModel):
    eventId: str
    timestamp: datetime
    domain: str
    url: str
    riskScore: int
    riskCategory: str
    severity: str
    confidence: str
    detectionIndicators: List[Dict[str, Any]]
    agentDispatches: Dict[str, Any]
    source: str
    schemaVersion: str
    clientIdentity: str
    createdAt: datetime

    model_config = ConfigDict(from_attributes=True)
