"""SentinelX Response Agent
Formulates proportionate, policy-aligned defensive recommendations.
Strictly advisory: never executes destructive actions or automatic file deletions.
"""

import time
from backend.app.agents.schemas import AgentExecutionResult, AgentStatus


class ResponseAgent:
    NAME = "ResponseAgent"

    async def execute(self, score: int, category: str, has_credential_risk: bool) -> AgentExecutionResult:
        start_time = time.time()

        if category == "Critical Risk" or score >= 75:
            recommendation = "IMMEDIATE BLOCK RECOMMENDED: Do not navigate to or interact with this site. Close tab immediately."
            policy_action = "block_recommended"
            priority = "critical"
        elif category == "High Risk" or score >= 50:
            if has_credential_risk:
                recommendation = "WARNING: Credential harvesting indicators detected. Under no circumstances submit passwords or payment details."
            else:
                recommendation = "WARNING: Significant security anomalies present. Avoid interaction and verify domain authenticity."
            policy_action = "warn_user"
            priority = "high"
        elif category == "Moderate Risk" or score >= 25:
            recommendation = "CAUTION: Unencrypted connection or unusual domain traits. Verify URL before submitting personal data."
            policy_action = "caution_advisory"
            priority = "moderate"
        else:
            recommendation = "SAFE: Website characteristics conform to expected security standards. Continue normal browsing."
            policy_action = "allow"
            priority = "low"

        elapsed = int((time.time() - start_time) * 1000)

        return AgentExecutionResult(
            agentName=self.NAME,
            status=AgentStatus.COMPLETED,
            executionTimeMs=elapsed,
            summary=f"Formulated defensive response: {policy_action} ({priority} priority).",
            data={
                "recommendation": recommendation,
                "policyAction": policy_action,
                "priority": priority
            },
            confidence="High"
        )
