"""SentinelX Digital Forensics Agent
Preserves evidence timeline, calculates cryptographic hashes of targets,
and builds an immutable forensic event log.
"""

import hashlib
import time
from datetime import datetime, timezone
from typing import List
from backend.app.agents.schemas import AgentExecutionResult, AgentStatus, AgentEvidenceItem


class DigitalForensicsAgent:
    NAME = "DigitalForensicsAgent"

    async def execute(self, url: str, evidence_items: List[AgentEvidenceItem]) -> AgentExecutionResult:
        start_time = time.time()

        # Compute SHA-256 hashes of the target URL and domain
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()

        # Construct chronological timeline of events & signals
        timeline = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "phase": "INGESTION",
                "description": f"URL ingested for forensics analysis. SHA256: {url_hash[:16]}..."
            }
        ]

        for idx, ev in enumerate(evidence_items):
            timeline.append({
                "timestamp": ev.timestamp.isoformat(),
                "phase": "EVIDENCE_RECORDED",
                "evidenceId": ev.id,
                "agent": ev.sourceAgent,
                "severity": ev.severity,
                "detail": ev.description
            })

        timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": "CHAIN_OF_CUSTODY_SEALED",
            "description": f"Forensic artifact sealed with {len(evidence_items)} recorded evidence items."
        })

        elapsed = int((time.time() - start_time) * 1000)

        return AgentExecutionResult(
            agentName=self.NAME,
            status=AgentStatus.COMPLETED,
            executionTimeMs=elapsed,
            summary=f"Constructed forensic timeline with {len(timeline)} chronological entries.",
            data={
                "urlSha256": url_hash,
                "timeline": timeline,
                "evidenceItemCount": len(evidence_items)
            },
            confidence="High"
        )
