"""SentinelX Threat Intelligence Provider Base
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ThreatIntelResult(BaseModel):
    provider: str
    indicator: str
    indicator_type: str  # domain, url, ip
    status: str          # clean, malicious, suspicious, unknown, unconfigured, error
    is_malicious: bool = False
    risk_score: int = 0  # 0 to 100
    confidence: str = "Low"
    details: Dict[str, Any] = Field(default_factory=dict)
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: Optional[str] = None


class BaseThreatIntelProvider(ABC):
    def __init__(self, name: str, api_key: Optional[str] = None, timeout: float = 4.0):
        self.name = name
        self.api_key = api_key
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        pass

    @abstractmethod
    async def lookup_url(self, url: str) -> ThreatIntelResult:
        pass
