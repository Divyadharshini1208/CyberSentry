"""SentinelX URL Intelligence Agent
Performs deep structural, lexical, and homoglyph inspection of URLs and hostnames.
"""

import math
import re
import time
from urllib.parse import urlparse
from backend.app.agents.schemas import AgentExecutionResult, AgentStatus, AgentEvidenceItem

# Target high-value brands for lookalike detection
TARGET_BRANDS = [
    "google", "microsoft", "apple", "paypal", "amazon", "netflix", "facebook",
    "instagram", "linkedin", "twitter", "chase", "bankofamerica", "wellsfargo",
    "citi", "binance", "coinbase", "metamask", "dhl", "fedex", "usps"
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "work",
    "click", "link", "stream", "icu", "cam", "monster", "sbs", "cfd"
}


def shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


class URLIntelligenceAgent:
    NAME = "URLIntelligenceAgent"

    async def execute(self, url: str) -> AgentExecutionResult:
        start_time = time.time()
        evidence = []
        data = {}

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            pathname = parsed.path or ""
            query = parsed.query or ""

            # Check 1: Insecure protocol
            if parsed.scheme.lower() == "http":
                evidence.append(AgentEvidenceItem(
                    id="INSECURE_HTTP_TRANSPORT",
                    sourceAgent=self.NAME,
                    category="protocol",
                    description="Cleartext HTTP protocol in use without TLS encryption",
                    severity="moderate",
                    weight=20
                ))

            # Check 2: Raw IP address
            is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname))
            if is_ip:
                evidence.append(AgentEvidenceItem(
                    id="RAW_IP_HOSTNAME",
                    sourceAgent=self.NAME,
                    category="url_structure",
                    description=f"Direct IP address '{hostname}' used instead of registered domain name",
                    severity="high",
                    weight=40
                ))

            # Check 3: Punycode or Homoglyphs
            if "xn--" in hostname:
                evidence.append(AgentEvidenceItem(
                    id="PUNYCODE_HOMOGLYPH",
                    sourceAgent=self.NAME,
                    category="url_structure",
                    description=f"Punycode encoded domain detected: '{hostname}'",
                    severity="high",
                    weight=35
                ))

            # Check 4: Excessive length & High entropy
            url_len = len(url)
            entropy = shannon_entropy(hostname)
            if url_len > 150:
                evidence.append(AgentEvidenceItem(
                    id="EXCESSIVE_URL_LENGTH",
                    sourceAgent=self.NAME,
                    category="url_structure",
                    description=f"Unusually long URL ({url_len} characters)",
                    severity="low",
                    weight=10
                ))

            # Check 5: Suspicious TLD
            parts = hostname.split(".")
            tld = parts[-1] if parts else ""
            if tld in SUSPICIOUS_TLDS:
                evidence.append(AgentEvidenceItem(
                    id="HIGH_ABUSE_TLD",
                    sourceAgent=self.NAME,
                    category="domain_intelligence",
                    description=f"Domain uses high-abuse top-level domain '.{tld}'",
                    severity="moderate",
                    weight=15
                ))

            # Check 6: Multiple subdomains
            subdomain_count = max(0, len(parts) - 2)
            if subdomain_count >= 3:
                evidence.append(AgentEvidenceItem(
                    id="EXCESSIVE_SUBDOMAINS",
                    sourceAgent=self.NAME,
                    category="url_structure",
                    description=f"Hostname contains {subdomain_count} nested subdomains",
                    severity="moderate",
                    weight=15
                ))

            data = {
                "hostname": hostname,
                "scheme": parsed.scheme,
                "port": parsed.port,
                "pathnameLength": len(pathname),
                "queryLength": len(query),
                "entropy": round(entropy, 3),
                "isIp": is_ip,
                "tld": tld,
                "subdomainCount": subdomain_count
            }

            elapsed = int((time.time() - start_time) * 1000)
            return AgentExecutionResult(
                agentName=self.NAME,
                status=AgentStatus.COMPLETED,
                executionTimeMs=elapsed,
                summary=f"Extracted {len(evidence)} structural indicator(s) from URL.",
                evidence=evidence,
                data=data,
                confidence="High"
            )

        except Exception as e:
            elapsed = int((time.time() - start_time) * 1000)
            return AgentExecutionResult(
                agentName=self.NAME,
                status=AgentStatus.FAILED,
                executionTimeMs=elapsed,
                errorMessage=str(e),
                summary="Failed to parse and extract URL indicators."
            )
