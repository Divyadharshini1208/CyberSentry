"""SentinelX Investigation Pydantic Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class InvestigationRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=4096)
    scanId: Optional[str] = Field(default=None, max_length=64)
    priority: Optional[str] = Field(default="normal", max_length=16)
    clientIdentity: Optional[str] = Field(default="default-client", max_length=128)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        clean = v.strip()
        if not (clean.startswith("http://") or clean.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return clean


class AgentReportSchema(BaseModel):
    agentName: str
    status: str
    executionTimeMs: int
    findings: Dict[str, Any]
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: str = Field(default="Medium")
    notes: Optional[str] = None


class InvestigationResponse(BaseModel):
    investigationId: str
    scanId: Optional[str] = None
    targetUrl: str
    domain: str
    status: str
    finalRiskScore: int
    finalVerdict: str
    confidence: str
    recommendedAction: str
    orchestratorSummary: str
    agentReports: Dict[str, Any]
    evidenceTimeline: List[Dict[str, Any]]
    createdAt: datetime
    completedAt: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
