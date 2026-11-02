"""SentinelX Risk Assessment Agent
Synthesizes evidence from deterministic analysis, phishing heuristics, and threat intelligence.
Applies bounded scoring rules (0-100) without double-counting correlated signals.
"""

import time
from typing import List
from backend.app.agents.schemas import AgentExecutionResult, AgentStatus, AgentEvidenceItem


class RiskAssessmentAgent:
    NAME = "RiskAssessmentAgent"

    async def execute(self, all_evidence: List[AgentEvidenceItem]) -> AgentExecutionResult:
        start_time = time.time()

        # Deduplicate evidence by ID to prevent double-counting
        unique_evidence = {}
        for ev in all_evidence:
            if ev.id not in unique_evidence:
                unique_evidence[ev.id] = ev

        items = list(unique_evidence.values())

        # Category breakdown
        category_weights = {
            "protocol": 0,
            "url_structure": 0,
            "domain_intelligence": 0,
            "phishing": 0,
            "threat_intelligence": 0
        }

        raw_score = 0
        has_critical = False

        for item in items:
            cat = item.category if item.category in category_weights else "url_structure"
            category_weights[cat] += item.weight
            raw_score += item.weight
            if item.severity == "critical":
                has_critical = True

        # Cap score between 0 and 100
        final_score = min(100, max(0, raw_score))

        # Determine Tier
        if final_score >= 75:
            category = "Critical Risk"
            verdict = "Malicious or High-Confidence Phishing Threat"
        elif final_score >= 50:
            category = "High Risk"
            verdict = "Suspicious Website with Deceptive Characteristics"
        elif final_score >= 25:
            category = "Moderate Risk"
            verdict = "Moderate Security Anomalies Detected"
        else:
            category = "Low Risk"
            verdict = "Standard Legitimate Website"

        # Determine confidence
        if has_critical or len(items) >= 3:
            confidence = "High"
        elif len(items) >= 1:
            confidence = "Medium"
        else:
            confidence = "Low"

        elapsed = int((time.time() - start_time) * 1000)

        return AgentExecutionResult(
            agentName=self.NAME,
            status=AgentStatus.COMPLETED,
            executionTimeMs=elapsed,
            summary=f"Synthesized {len(items)} evidence item(s) -> Score {final_score}/100 ({category}).",
            data={
                "finalScore": final_score,
                "category": category,
                "verdict": verdict,
                "confidence": confidence,
                "categoryBreakdown": category_weights,
                "evidenceCount": len(items)
            },
            confidence=confidence
        )
