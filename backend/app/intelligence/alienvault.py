"""SentinelX AlienVault OTX Adapter
"""

from typing import Optional
from urllib.parse import urlparse
import httpx
from backend.app.core.logging import logger
from backend.app.intelligence.base import BaseThreatIntelProvider, ThreatIntelResult


class AlienVaultOTXAdapter(BaseThreatIntelProvider):
    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 4.0):
        super().__init__(name="alienvault_otx", api_key=api_key, timeout=timeout)

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        if not self.is_configured:
            return ThreatIntelResult(
                provider=self.name,
                indicator=domain,
                indicator_type="domain",
                status="unconfigured",
                details={"message": "AlienVault OTX API key not configured."}
            )

        headers = {"X-OTX-API-KEY": self.api_key}
        endpoint = f"{self.BASE_URL}/indicators/domain/{domain}/general"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    pulses = pulse_info.get("pulses", [])

                    threat_names = [p.get("name") for p in pulses[:5] if p.get("name")]
                    tags = list({t for p in pulses for t in p.get("tags", [])})[:10]

                    is_mal = pulse_count >= 2
                    risk = min(100, pulse_count * 25)
                    status = "malicious" if is_mal else ("suspicious" if pulse_count == 1 else "clean")

                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=domain,
                        indicator_type="domain",
                        status=status,
                        is_malicious=is_mal,
                        risk_score=risk,
                        confidence="High" if pulse_count >= 3 else "Medium",
                        details={
                            "pulseCount": pulse_count,
                            "threatNames": threat_names,
                            "tags": tags
                        }
                    )
                elif resp.status_code == 404:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=domain,
                        indicator_type="domain",
                        status="clean",
                        details={"pulseCount": 0}
                    )
                else:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=domain,
                        indicator_type="domain",
                        status="error",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except Exception as e:
            logger.warning(f"[AlienVault OTX] Lookup error for {domain}: {e}")
            return ThreatIntelResult(
                provider=self.name,
                indicator=domain,
                indicator_type="domain",
                status="error",
                error_message=str(e)
            )

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        # Fall back to domain lookup for AlienVault
        domain = urlparse(url).netloc.split(":")[0]
        return await self.lookup_domain(domain)
