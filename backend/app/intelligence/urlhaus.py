"""SentinelX URLhaus Adapter (abuse.ch)
"""

from typing import Optional
from urllib.parse import urlparse
import httpx
from backend.app.core.logging import logger
from backend.app.intelligence.base import BaseThreatIntelProvider, ThreatIntelResult


class URLhausAdapter(BaseThreatIntelProvider):
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 4.0):
        # URLhaus allows public querying or auth key for elevated limits
        super().__init__(name="urlhaus", api_key=api_key, timeout=timeout)

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        if not self.is_configured:
            return ThreatIntelResult(
                provider=self.name,
                indicator=url,
                indicator_type="url",
                status="unconfigured",
                is_malicious=False,
                risk_score=0,
                confidence="Low",
                details={"message": "URLhaus API key not configured."}
            )

        endpoint = f"{self.BASE_URL}/url/"
        data = {"url": url}
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(endpoint, data=data, headers=headers)
                if resp.status_code == 200:
                    res = resp.json()
                    query_status = res.get("query_status")

                    if query_status == "ok":
                        threat = res.get("threat", "malware")
                        url_status = res.get("url_status", "offline")
                        tags = res.get("tags") or []

                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=url,
                            indicator_type="url",
                            status="malicious",
                            is_malicious=True,
                            risk_score=95,
                            confidence="High",
                            details={
                                "threat": threat,
                                "urlStatus": url_status,
                                "tags": tags,
                                "reporter": res.get("reporter")
                            }
                        )
                    elif query_status == "no_results":
                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=url,
                            indicator_type="url",
                            status="clean",
                            is_malicious=False,
                            risk_score=0,
                            confidence="Medium",
                            details={"queryStatus": "no_results"}
                        )
                    else:
                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=url,
                            indicator_type="url",
                            status="unknown",
                            details={"queryStatus": query_status}
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
            logger.warning(f"[URLhaus] URL lookup error: {e}")
            return ThreatIntelResult(
                provider=self.name,
                indicator=url,
                indicator_type="url",
                status="error",
                error_message=str(e)
            )

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        if not self.is_configured:
            return ThreatIntelResult(
                provider=self.name,
                indicator=domain,
                indicator_type="domain",
                status="unconfigured",
                is_malicious=False,
                risk_score=0,
                confidence="Low",
                details={"message": "URLhaus API key not configured."}
            )

        endpoint = f"{self.BASE_URL}/host/"
        data = {"host": domain}
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(endpoint, data=data, headers=headers)
                if resp.status_code == 200:
                    res = resp.json()
                    query_status = res.get("query_status")

                    if query_status == "ok":
                        url_count = int(res.get("url_count") or 0)
                        is_mal = url_count > 0
                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=domain,
                            indicator_type="domain",
                            status="malicious" if is_mal else "clean",
                            is_malicious=is_mal,
                            risk_score=90 if is_mal else 0,
                            confidence="High",
                            details={"urlCount": url_count, "urls": (res.get("urls") or [])[:5]}
                        )
                    else:
                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=domain,
                            indicator_type="domain",
                            status="clean",
                            details={"queryStatus": query_status}
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
            logger.warning(f"[URLhaus] Domain lookup error: {e}")
            return ThreatIntelResult(
                provider=self.name,
                indicator=domain,
                indicator_type="domain",
                status="error",
                error_message=str(e)
            )
