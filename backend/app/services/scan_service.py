"""SentinelX URL Scan Service
Orchestrates SSRF validation, deterministic URL heuristics, threat intelligence, and ML prediction.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.logging import logger
from backend.app.models.url_scan import UrlScan
from backend.app.repositories.scan_repo import ScanRepository
from backend.app.repositories.audit_repo import AuditRepository
from backend.app.schemas.scan import UrlScanRequest, UrlScanResponse
from backend.app.security.ssrf_guard import validate_url_for_outbound
from backend.app.intelligence.manager import threat_intel_manager
from backend.app.ml.model import url_classifier
from backend.app.agents.url_intelligence import URLIntelligenceAgent
from backend.app.agents.phishing_analysis import PhishingAnalysisAgent


class ScanService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ScanRepository(session)
        self.audit_repo = AuditRepository(session)
        self.url_agent = URLIntelligenceAgent()
        self.phishing_agent = PhishingAnalysisAgent()

    async def execute_scan(self, req: UrlScanRequest, ip_address: str = "unknown") -> UrlScanResponse:
        # 1. SSRF Guard verification
        validate_url_for_outbound(req.url)

        scan_id = f"scn_{uuid.uuid4().hex[:12]}"
        domain = urlparse(req.url).netloc.split(":")[0].lower()

        # 2. Local deterministic & phishing analysis
        url_res = await self.url_agent.execute(req.url)
        phishing_res = await self.phishing_agent.execute(req.url)

        local_indicators = []
        raw_score = 0
        reasons = []

        for ev in (url_res.evidence + phishing_res.evidence):
            local_indicators.append({
                "id": ev.id,
                "name": ev.description,
                "category": ev.category,
                "severity": ev.severity,
                "weight": ev.weight
            })
            raw_score += ev.weight
            reasons.append(ev.description)

        # 3. Threat Intelligence enrichment (if enabled)
        threat_intel_summary = {}
        if req.enableThreatIntel:
            threat_intel_summary = await threat_intel_manager.lookup(req.url)
            if threat_intel_summary.get("isMalicious"):
                raw_score += threat_intel_summary.get("maxRiskScore", 50)
                reasons.extend(threat_intel_summary.get("reasons", []))

        # 4. ML Prediction (if enabled)
        ml_prediction = {}
        if req.enableMl:
            ml_prediction = url_classifier.predict(req.url)
            if ml_prediction.get("prediction") == "malicious":
                # ML prediction adds calibrated weight if above 75% probability
                if ml_prediction.get("probability", 0) >= 0.75:
                    raw_score += 25
                    reasons.append(f"ML Classifier flagged high malicious probability ({int(ml_prediction['probability']*100)}%)")

        final_score = min(100, max(0, raw_score))

        if final_score >= 75:
            category = "Critical Risk"
            severity = "critical"
            action = "Leave website immediately. Do not enter credentials."
        elif final_score >= 50:
            category = "High Risk"
            severity = "high"
            action = "Significant threats identified. Avoid submitting personal data."
        elif final_score >= 25:
            category = "Moderate Risk"
            severity = "moderate"
            action = "Exercise caution. Verify website domain spelling."
        else:
            category = "Low Risk"
            severity = "low"
            action = "Safe to browse. Standard security characteristics verified."

        if not reasons:
            reasons.append("No security anomalies detected.")

        scan_record = UrlScan(
            scan_id=scan_id,
            target_url=req.url,
            domain=domain,
            status="completed",
            risk_score=final_score,
            risk_category=category,
            confidence="High" if final_score >= 70 or threat_intel_summary.get("isMalicious") else "Medium",
            local_indicators=local_indicators,
            threat_intel_summary=threat_intel_summary,
            ml_prediction=ml_prediction,
            reasons=reasons,
            recommended_action=action,
            client_identity=req.clientIdentity or "default-client",
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )

        saved = await self.repo.create(scan_record)

        # Audit log for scans
        await self.audit_repo.log_action(
            action="URL_SCAN",
            actor=req.clientIdentity or "default-client",
            resource_type="scan",
            resource_id=scan_id,
            details={"url": req.url, "domain": domain, "score": final_score, "category": category},
            ip_address=ip_address
        )

        return UrlScanResponse(
            scanId=saved.scan_id,
            targetUrl=saved.target_url,
            domain=saved.domain,
            status=saved.status,
            riskScore=saved.risk_score,
            riskCategory=saved.risk_category,
            severity=severity,
            confidence=saved.confidence,
            reasons=saved.reasons,
            recommendedAction=saved.recommended_action,
            localIndicators=saved.local_indicators,
            threatIntelSummary=saved.threat_intel_summary,
            mlPrediction=saved.ml_prediction,
            createdAt=saved.created_at,
            completedAt=saved.completed_at
        )

    async def get_scan_by_id(self, scan_id: str) -> Optional[UrlScanResponse]:
        scan = await self.repo.get_by_scan_id(scan_id)
        if not scan:
            return None

        severity = "low"
        if scan.risk_score >= 75:
            severity = "critical"
        elif scan.risk_score >= 50:
            severity = "high"
        elif scan.risk_score >= 25:
            severity = "moderate"

        return UrlScanResponse(
            scanId=scan.scan_id,
            targetUrl=scan.target_url,
            domain=scan.domain,
            status=scan.status,
            riskScore=scan.risk_score,
            riskCategory=scan.risk_category,
            severity=severity,
            confidence=scan.confidence,
            reasons=scan.reasons,
            recommendedAction=scan.recommended_action,
            localIndicators=scan.local_indicators,
            threatIntelSummary=scan.threat_intel_summary,
            mlPrediction=scan.ml_prediction,
            createdAt=scan.created_at,
            completedAt=scan.completed_at
        )
