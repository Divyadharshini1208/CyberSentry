"""SentinelX Threat Intelligence Agent
Correlates findings across VirusTotal, AlienVault OTX, and URLhaus.
"""

import time
from backend.app.agents.schemas import AgentExecutionResult, AgentStatus, AgentEvidenceItem
from backend.app.intelligence.manager import threat_intel_manager


class ThreatIntelligenceAgent:
    NAME = "ThreatIntelligenceAgent"

    async def execute(self, url: str) -> AgentExecutionResult:
        start_time = time.time()
        evidence = []

        try:
            lookup_result = await threat_intel_manager.lookup(url)
            is_malicious = lookup_result.get("isMalicious", False)
            positive_detections = lookup_result.get("positiveDetections", 0)
            providers = lookup_result.get("providerResults", {})

            for provider_name, res in providers.items():
                if res.get("isMalicious"):
                    evidence.append(AgentEvidenceItem(
                        id=f"THREAT_INTEL_{provider_name.upper()}_MALICIOUS",
                        sourceAgent=self.NAME,
                        category="threat_intelligence",
                        description=f"Listed as malicious by {provider_name.upper()}",
                        severity="critical",
                        weight=60,
                        rawSignal=res
                    ))
                elif res.get("status") == "suspicious":
                    evidence.append(AgentEvidenceItem(
                        id=f"THREAT_INTEL_{provider_name.upper()}_SUSPICIOUS",
                        sourceAgent=self.NAME,
                        category="threat_intelligence",
                        description=f"Flagged as suspicious by {provider_name.upper()}",
                        severity="moderate",
                        weight=30,
                        rawSignal=res
                    ))

            elapsed = int((time.time() - start_time) * 1000)
            status = AgentStatus.COMPLETED

            summary = f"Queried {len(providers)} provider(s); Detections: {positive_detections} positive."

            return AgentExecutionResult(
                agentName=self.NAME,
                status=status,
                executionTimeMs=elapsed,
                summary=summary,
                evidence=evidence,
                data=lookup_result,
                confidence="High" if positive_detections > 0 else "Medium"
            )

        except Exception as e:
            elapsed = int((time.time() - start_time) * 1000)
            return AgentExecutionResult(
                agentName=self.NAME,
                status=AgentStatus.FAILED,
                executionTimeMs=elapsed,
                errorMessage=str(e),
                summary="Threat intelligence lookup failed."
            )
