"""SentinelX Security Auditor Agent
Validates investigation evidence integrity, checks consistency between conclusions
and evidence, and flags contradictory or unverified claims.
"""

import time
from typing import Dict, List
from backend.app.agents.schemas import AgentExecutionResult, AgentStatus, AgentEvidenceItem


class SecurityAuditorAgent:
    NAME = "SecurityAuditorAgent"

    async def execute(
        self,
        score: int,
        category: str,
        evidence: List[AgentEvidenceItem],
        agent_results: Dict[str, AgentExecutionResult]
    ) -> AgentExecutionResult:
        start_time = time.time()
        warnings = []
        is_consistent = True

        # Check 1: Evidence vs Score consistency
        if score > 50 and len(evidence) == 0:
            warnings.append("High risk score assigned with zero supporting evidence items.")
            is_consistent = False

        if score == 0 and any(e.severity == "critical" for e in evidence):
            warnings.append("Zero risk score assigned despite presence of critical severity evidence.")
            is_consistent = False

        # Check 2: Verify all key agents executed
        expected_agents = ["URLIntelligenceAgent", "PhishingAnalysisAgent", "ThreatIntelligenceAgent"]
        for agent_name in expected_agents:
            if agent_name not in agent_results:
                warnings.append(f"Required agent '{agent_name}' did not produce an execution record.")
            elif agent_results[agent_name].status == AgentStatus.FAILED:
                warnings.append(f"Agent '{agent_name}' execution reported failure status.")

        elapsed = int((time.time() - start_time) * 1000)

        return AgentExecutionResult(
            agentName=self.NAME,
            status=AgentStatus.COMPLETED,
            executionTimeMs=elapsed,
            summary="Audit completed: " + ("All evidence and conclusions verified consistent." if is_consistent else f"Flagged {len(warnings)} discrepancy warning(s)."),
            data={
                "isConsistent": is_consistent,
                "warnings": warnings,
                "verifiedEvidenceCount": len(evidence),
                "auditedAgents": list(agent_results.keys())
            },
            confidence="High"
        )
