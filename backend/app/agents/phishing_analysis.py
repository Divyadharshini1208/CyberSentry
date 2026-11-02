"""SentinelX Phishing Analysis Agent
Specializes in brand impersonation, typosquatting, deceptive login endpoints,
and credential harvesting heuristics.
"""

import re
import time
from urllib.parse import urlparse, parse_qs
from backend.app.agents.schemas import AgentExecutionResult, AgentStatus, AgentEvidenceItem
from backend.app.agents.url_intelligence import TARGET_BRANDS

LOGIN_KEYWORDS = [
    "login", "signin", "log-in", "sign-in", "logon", "authenticate",
    "auth", "verification", "verify", "account-update", "security-challenge",
    "webscr", "wallet", "banking", "billing", "recover"
]


def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def detect_typosquatting(candidate: str, brand: str) -> bool:
    if not candidate or candidate == brand:
        return False
    norm = candidate.replace("0", "o").replace("1", "l").replace("vv", "w").replace("rn", "m")
    if norm == brand:
        return True
    dist = levenshtein(candidate, brand)
    return dist == 1 or (len(brand) >= 7 and dist == 2)


class PhishingAnalysisAgent:
    NAME = "PhishingAnalysisAgent"

    async def execute(self, url: str) -> AgentExecutionResult:
        start_time = time.time()
        evidence = []
        impersonated_brand = None

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            query = parsed.query or ""

            # Check 1: Brand Typosquatting / Lookalikes in hostname
            parts = hostname.split(".")
            root_candidate = parts[-2] if len(parts) >= 2 else hostname
            tokens = root_candidate.split("-")

            for brand in TARGET_BRANDS:
                # Direct match in unofficial domain
                if detect_typosquatting(root_candidate, brand) or any(detect_typosquatting(t, brand) for t in tokens):
                    impersonated_brand = brand
                    evidence.append(AgentEvidenceItem(
                        id="LOOKALIKE_BRAND_DOMAIN",
                        sourceAgent=self.NAME,
                        category="phishing",
                        description=f"Domain closely mimics protected brand '{brand}' via character substitution/typosquatting",
                        severity="critical",
                        weight=50
                    ))
                    break
                elif brand in root_candidate and not root_candidate.startswith(brand + "."):
                    # e.g. paypal-security-portal.xyz
                    impersonated_brand = brand
                    evidence.append(AgentEvidenceItem(
                        id="BRAND_KEYWORD_IMPERSONATION",
                        sourceAgent=self.NAME,
                        category="phishing",
                        description=f"Domain incorporates brand keyword '{brand}' in an unofficial composite structure",
                        severity="high",
                        weight=40
                    ))
                    break

            # Check 2: Deceptive Authentication Endpoints
            has_login_endpoint = any(kw in path for kw in LOGIN_KEYWORDS)
            if has_login_endpoint:
                if impersonated_brand or evidence:
                    evidence.append(AgentEvidenceItem(
                        id="DECEPTIVE_AUTH_ENDPOINT",
                        sourceAgent=self.NAME,
                        category="phishing",
                        description=f"Authentication/login path found on an unverified lookalike domain ({path})",
                        severity="critical",
                        weight=45
                    ))
                else:
                    evidence.append(AgentEvidenceItem(
                        id="LOGIN_PATH_OBSERVED",
                        sourceAgent=self.NAME,
                        category="phishing",
                        description=f"Authentication path endpoint observed ({path})",
                        severity="low",
                        weight=10
                    ))

            # Check 3: Suspicious Open Redirect Query Parameters
            qs = parse_qs(query)
            for k, vals in qs.items():
                if k.lower() in ("redirect", "redirect_url", "return_url", "dest", "next", "goto"):
                    for v in vals:
                        if v.startswith("http://") or v.startswith("https://"):
                            evidence.append(AgentEvidenceItem(
                                id="OPEN_REDIRECT_TARGET",
                                sourceAgent=self.NAME,
                                category="phishing",
                                description=f"Open redirect query parameter '{k}' pointing to external URL: {v[:80]}",
                                severity="moderate",
                                weight=25
                            ))
                            break

            elapsed = int((time.time() - start_time) * 1000)
            return AgentExecutionResult(
                agentName=self.NAME,
                status=AgentStatus.COMPLETED,
                executionTimeMs=elapsed,
                summary=f"Identified {len(evidence)} phishing signal(s); Brand: {impersonated_brand or 'None'}.",
                evidence=evidence,
                data={
                    "impersonatedBrand": impersonated_brand,
                    "hasLoginEndpoint": has_login_endpoint,
                    "signalCount": len(evidence)
                },
                confidence="High" if impersonated_brand else "Medium"
            )

        except Exception as e:
            elapsed = int((time.time() - start_time) * 1000)
            return AgentExecutionResult(
                agentName=self.NAME,
                status=AgentStatus.FAILED,
                executionTimeMs=elapsed,
                errorMessage=str(e),
                summary="Phishing analysis failed due to parsing exception."
            )
