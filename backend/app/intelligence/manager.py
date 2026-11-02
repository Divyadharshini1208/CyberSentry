"""SentinelX Threat Intelligence Manager
Orchestrates parallel provider lookups, caching, deduplication, and normalized synthesis.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.intelligence.base import ThreatIntelResult
from backend.app.intelligence.virustotal import VirusTotalAdapter
from backend.app.intelligence.alienvault import AlienVaultOTXAdapter
from backend.app.intelligence.urlhaus import URLhausAdapter


class ThreatIntelManager:
    def __init__(self):
        self.vt = VirusTotalAdapter(
            api_key=settings.VIRUSTOTAL_API_KEY,
            timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS
        )
        self.otx = AlienVaultOTXAdapter(
            api_key=settings.ALIENVAULT_OTX_API_KEY,
            timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS
        )
        self.urlhaus = URLhausAdapter(
            api_key=settings.URLHAUS_AUTH_KEY,
            timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS
        )

        # In-memory fast cache: indicator -> (ThreatIntelResult, expire_timestamp)
        self._cache: Dict[str, tuple[ThreatIntelResult, float]] = {}

    def get_providers_status(self) -> Dict[str, bool]:
        """Returns the configuration status of each provider."""
        return {
            "virustotal": self.vt.is_configured,
            "alienvault_otx": self.otx.is_configured,
            "urlhaus": True  # URLhaus public API available
        }

    async def lookup(self, url: str) -> Dict[str, Any]:
        """Queries configured threat intelligence feeds in parallel and synthesizes results."""
        domain = urlparse(url).netloc.split(":")[0].lower()
        now = datetime.now(timezone.utc).timestamp()

        # Check in-memory cache
        cache_key = f"ti:{url}"
        if cache_key in self._cache:
            res, expires = self._cache[cache_key]
            if now < expires:
                return res

        # Run provider lookups with error isolation
        results = []
        for coro in [self.vt.lookup_url(url), self.otx.lookup_domain(domain), self.urlhaus.lookup_url(url)]:
            try:
                res = await coro
                results.append(res)
            except Exception as e:
                logger.warning(f"Threat intel task exception: {e}")
                results.append(e)

        provider_results = {}
        total_malicious = 0
        max_risk_score = 0
        configured_count = 0
        reasons = []

        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"Threat intel task exception: {r}")
                continue
            if isinstance(r, ThreatIntelResult):
                provider_results[r.provider] = {
                    "status": r.status,
                    "isMalicious": r.is_malicious,
                    "riskScore": r.risk_score,
                    "confidence": r.confidence,
                    "details": r.details,
                    "error": r.error_message
                }
                if r.status != "unconfigured":
                    configured_count += 1
                if r.is_malicious:
                    total_malicious += 1
                    reasons.append(f"Flagged as malicious by {r.provider}")
                if r.risk_score > max_risk_score:
                    max_risk_score = r.risk_score

        # Consolidated status
        overall_status = "clean"
        if total_malicious >= 1:
            overall_status = "malicious"
        elif configured_count == 0:
            overall_status = "unconfigured"

        synthesis = {
            "url": url,
            "domain": domain,
            "overallStatus": overall_status,
            "isMalicious": total_malicious >= 1,
            "maxRiskScore": max_risk_score,
            "positiveDetections": total_malicious,
            "configuredProviders": configured_count,
            "providerResults": provider_results,
            "reasons": reasons,
            "evaluatedAt": datetime.now(timezone.utc).isoformat()
        }

        # Cache result
        self._cache[cache_key] = (synthesis, now + settings.THREAT_INTEL_CACHE_TTL_SECONDS)
        return synthesis


threat_intel_manager = ThreatIntelManager()
