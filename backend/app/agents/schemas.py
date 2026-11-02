"""SentinelX Multi-Agent Investigation Schemas
Defines strict Pydantic models for agent inputs, outputs, states, and evidence.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"


class AgentEvidenceItem(BaseModel):
    id: str
    sourceAgent: str
    category: str
    description: str
    severity: str = "moderate"
    weight: int = 0
    rawSignal: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentExecutionResult(BaseModel):
    agentName: str
    status: AgentStatus
    executionTimeMs: int = 0
    summary: str = ""
    evidence: List[AgentEvidenceItem] = Field(default_factory=list)
    data: Dict[str, Any] = Field(default_factory=dict)
    confidence: str = "Medium"
    errorMessage: Optional[str] = None
    startedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completedAt: Optional[datetime] = None


class InvestigationState(BaseModel):
    investigationId: str
    targetUrl: str
    domain: str
    scanId: Optional[str] = None
    clientIdentity: str = "default-client"
    status: str = "pending"

    # Execution tracking
    agentResults: Dict[str, AgentExecutionResult] = Field(default_factory=dict)
    evidenceTimeline: List[Dict[str, Any]] = Field(default_factory=list)

    # Synthesis
    finalRiskScore: int = 0
    finalCategory: str = "Low Risk"
    finalVerdict: str = "Inconclusive"
    confidence: str = "Medium"
    recommendedAction: str = "Continue monitoring"
    orchestratorSummary: str = ""
    auditedSuccessfully: bool = False
    auditWarnings: List[str] = Field(default_factory=list)

    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completedAt: Optional[datetime] = None
