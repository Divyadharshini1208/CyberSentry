"""SentinelX URL Scan Pydantic Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator, ConfigDict


class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=4096, description="Target URL to inspect")
    enableThreatIntel: bool = Field(default=True, description="Query configured threat intel feeds")
    enableMl: bool = Field(default=True, description="Run ML classifier model")
    clientIdentity: Optional[str] = Field(default="default-client", max_length=128)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        clean = v.strip()
        if not (clean.startswith("http://") or clean.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return clean


class UrlScanResponse(BaseModel):
    scanId: str
    targetUrl: str
    domain: str
    status: str
    riskScore: int
    riskCategory: str
    severity: str
    confidence: str
    reasons: List[str]
    recommendedAction: str
    localIndicators: List[Dict[str, Any]]
    threatIntelSummary: Dict[str, Any]
    mlPrediction: Dict[str, Any]
    createdAt: datetime
    completedAt: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
