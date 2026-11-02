"""SentinelX VirusTotal v3 Adapter
"""

import base64
from typing import Optional
import httpx
from backend.app.core.logging import logger
from backend.app.intelligence.base import BaseThreatIntelProvider, ThreatIntelResult


class VirusTotalAdapter(BaseThreatIntelProvider):
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 4.0):
        super().__init__(name="virustotal", api_key=api_key, timeout=timeout)

    def _url_to_id(self, url: str) -> str:
        """VirusTotal v3 requires URL identifiers to be base64-encoded without padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        if not self.is_configured:
            return ThreatIntelResult(
                provider=self.name,
                indicator=domain,
                indicator_type="domain",
                status="unconfigured",
                details={"message": "VirusTotal API key not configured. Operating in local heuristic mode."}
            )

        headers = {"x-apikey": self.api_key}
        endpoint = f"{self.BASE_URL}/domains/{domain}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1

                    is_mal = malicious >= 2
                    risk = min(100, int((malicious * 20) + (suspicious * 10)))

                    status = "malicious" if is_mal else ("suspicious" if suspicious > 0 or malicious > 0 else "clean")

                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=domain,
                        indicator_type="domain",
                        status=status,
                        is_malicious=is_mal,
                        risk_score=risk,
                        confidence="High" if total >= 10 else "Medium",
                        details={
                            "reputation": attributes.get("reputation", 0),
                            "stats": stats,
                            "categories": attributes.get("categories", {})
                        }
                    )
                elif resp.status_code == 404:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=domain,
                        indicator_type="domain",
                        status="unknown",
                        details={"message": "Domain not found in VirusTotal dataset"}
                    )
                elif resp.status_code == 429:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=domain,
                        indicator_type="domain",
                        status="error",
                        error_message="VirusTotal rate limit exceeded"
                    )
                else:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=domain,
                        indicator_type="domain",
                        status="error",
                        error_message=f"HTTP {resp.status_code}: {resp.text[:100]}"
                    )
        except Exception as e:
            logger.warning(f"[VirusTotal] Lookup error for {domain}: {e}")
            return ThreatIntelResult(
                provider=self.name,
                indicator=domain,
                indicator_type="domain",
                status="error",
                error_message=str(e)
            )

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        if not self.is_configured:
            return ThreatIntelResult(
                provider=self.name,
                indicator=url,
                indicator_type="url",
                status="unconfigured",
                details={"message": "VirusTotal API key not configured."}
            )

        url_id = self._url_to_id(url)
        headers = {"x-apikey": self.api_key}
        endpoint = f"{self.BASE_URL}/urls/{url_id}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    is_mal = malicious >= 2
                    risk = min(100, int((malicious * 25) + (suspicious * 10)))
                    status = "malicious" if is_mal else ("suspicious" if suspicious > 0 or malicious > 0 else "clean")

                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=url,
                        indicator_type="url",
                        status=status,
                        is_malicious=is_mal,
                        risk_score=risk,
                        confidence="High",
                        details={"stats": stats}
                    )
                elif resp.status_code == 404:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=url,
                        indicator_type="url",
                        status="unknown",
                        details={"message": "URL not found in VirusTotal dataset"}
                    )
                else:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=url,
                        indicator_type="url",
                        status="error",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except Exception as e:
            logger.warning(f"[VirusTotal] URL lookup error: {e}")
            return ThreatIntelResult(
                provider=self.name,
                indicator=url,
                indicator_type="url",
                status="error",
                error_message=str(e)
            )
