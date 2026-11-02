/**
 * SentinelX – Website Risk Scoring Engine
 * Computes transparent, deterministic risk scores (0–100), risk tiers, confidence,
 * actionable recommendations, and AI-ready security event telemetry.
 */

export const RiskTiers = {
  LOW: {
    name: 'Low Risk',
    severity: 'low',
    min: 0,
    max: 24,
    color: '#10b981', // Emerald green
    recommendedAction: 'Site appears safe. Continue normal browsing.'
  },
  MODERATE: {
    name: 'Moderate Risk',
    severity: 'moderate',
    min: 25,
    max: 49,
    color: '#f59e0b', // Amber
    recommendedAction: 'Exercise caution. Verify the domain address before submitting sensitive details.'
  },
  HIGH: {
    name: 'High Risk',
    severity: 'high',
    min: 50,
    max: 74,
    color: '#f97316', // Orange
    recommendedAction: 'High risk indicators detected. Do not enter credentials, credit cards, or personal data.'
  },
  CRITICAL: {
    name: 'Critical Risk',
    severity: 'critical',
    min: 75,
    max: 100,
    color: '#ef4444', // Red
    recommendedAction: 'Severe threat indicators identified. Leave this website or close the tab immediately.'
  }
};

export const RiskEngine = {
  /**
   * Determine the risk tier object based on score (0-100)
   */
  getTier(score) {
    const clamped = Math.max(0, Math.min(100, Math.round(score)));
    if (clamped >= RiskTiers.CRITICAL.min) return { ...RiskTiers.CRITICAL, score: clamped };
    if (clamped >= RiskTiers.HIGH.min) return { ...RiskTiers.HIGH, score: clamped };
    if (clamped >= RiskTiers.MODERATE.min) return { ...RiskTiers.MODERATE, score: clamped };
    return { ...RiskTiers.LOW, score: clamped };
  },

  /**
   * Main score calculation combining URL scan, Phishing evaluation, and Redirect chain
   */
  evaluate({
    urlScan,
    phishingEval,
    redirectEval = null,
    isAllowlisted = false,
    isBlocklisted = false
  }) {
    const timestamp = new Date().toISOString();
    const eventId = `evt_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

    const domain = (urlScan && urlScan.domainStructure) ? urlScan.domainStructure.rootDomain : (urlScan ? urlScan.hostname : 'unknown');
    const url = urlScan ? urlScan.url : '';

    // Handle user policy overrides first
    if (isBlocklisted) {
      const blockTier = RiskTiers.CRITICAL;
      const indicator = {
        id: 'USER_BLOCKLISTED_DOMAIN',
        name: 'Domain in User Blocklist',
        description: `The domain "${domain}" is on your personal blocklist.`,
        severity: 'critical',
        weight: 100,
        scoreContribution: 100,
        category: 'user_policy'
      };

      return this.formatResult({
        eventId,
        timestamp,
        domain,
        url,
        score: 100,
        tier: blockTier,
        confidence: 'High',
        indicators: [indicator],
        reasons: [`Website is blocked by user policy (${domain}).`],
        recommendedAction: 'Access is blocked by user policy. Close tab or modify blocklist in settings.',
        isBlocklisted: true,
        isAllowlisted: false,
        breakdown: { user_policy: 100 },
        threatIntelStatus: 'local_policy_enforcement'
      });
    }

    if (isAllowlisted) {
      const allowTier = RiskTiers.LOW;
      const indicator = {
        id: 'USER_ALLOWLISTED_DOMAIN',
        name: 'Domain in User Allowlist',
        description: `The domain "${domain}" is explicitly trusted in your settings.`,
        severity: 'low',
        weight: 0,
        scoreContribution: 0,
        category: 'user_policy'
      };

      return this.formatResult({
        eventId,
        timestamp,
        domain,
        url,
        score: 0,
        tier: allowTier,
        confidence: 'High',
        indicators: [indicator],
        reasons: [`Domain is trusted via user allowlist (${domain}).`],
        recommendedAction: 'Trusted domain in user allowlist. Safe to browse.',
        isBlocklisted: false,
        isAllowlisted: true,
        breakdown: { user_policy: 0 },
        threatIntelStatus: 'local_policy_enforcement'
      });
    }

    // Aggregate indicators from all detection modules
    const indicatorMap = new Map();

    const addIndicator = (ind) => {
      if (!ind || !ind.id) return;
      if (!indicatorMap.has(ind.id)) {
        indicatorMap.set(ind.id, {
          ...ind,
          scoreContribution: ind.weight || 0
        });
      }
    };

    if (urlScan && Array.isArray(urlScan.indicators)) {
      urlScan.indicators.forEach(addIndicator);
    }
    if (phishingEval && Array.isArray(phishingEval.indicators)) {
      phishingEval.indicators.forEach(addIndicator);
    }
    if (redirectEval && Array.isArray(redirectEval.indicators)) {
      redirectEval.indicators.forEach(addIndicator);
    }

    const allIndicators = Array.from(indicatorMap.values());

    // Calculate category breakdown
    const breakdown = {
      protocol: 0,
      url_structure: 0,
      domain_intelligence: 0,
      phishing: 0,
      redirect: 0
    };

    let rawScore = 0;
    allIndicators.forEach(ind => {
      const cat = ind.category || 'url_structure';
      if (breakdown[cat] !== undefined) {
        breakdown[cat] += ind.scoreContribution;
      }
      rawScore += ind.scoreContribution;
    });

    // Special mitigation: If the domain is in KNOWN_SAFE_DOMAINS and there is NO critical indicator (e.g. homoglyph / @ exploit)
    const hasCritical = allIndicators.some(i => i.severity === 'critical');
    if (urlScan && urlScan.isKnownSafe && !hasCritical) {
      // Known safe sites should not get false positives from long URLs or non-sensitive parameters
      rawScore = Math.min(15, rawScore);
    }

    // Cap final score between 0 and 100
    const finalScore = Math.min(100, Math.max(0, rawScore));
    const tier = this.getTier(finalScore);

    // Human-readable reasons
    const reasons = [];
    if (allIndicators.length === 0) {
      reasons.push('No suspicious indicators or security anomalies detected.');
      reasons.push('Standard HTTPS encryption in use with normal domain structure.');
    } else {
      allIndicators.forEach(ind => {
        reasons.push(`${ind.name}: ${ind.description}`);
      });
    }

    // Determine Confidence level
    let confidence = 'Medium';
    if (allIndicators.length >= 2 || finalScore >= 70 || (urlScan && urlScan.isKnownSafe)) {
      confidence = 'High';
    } else if (allIndicators.length === 1 && finalScore < 30) {
      confidence = 'Low';
    }

    return this.formatResult({
      eventId,
      timestamp,
      domain,
      url,
      score: finalScore,
      tier,
      confidence,
      indicators: allIndicators,
      reasons,
      recommendedAction: tier.recommendedAction,
      isBlocklisted: false,
      isAllowlisted: false,
      breakdown,
      threatIntelStatus: 'local_heuristic_evaluation'
    });
  },

  /**
   * Structure standard AI-ready security event
   */
  formatResult({
    eventId,
    timestamp,
    domain,
    url,
    score,
    tier,
    confidence,
    indicators,
    reasons,
    recommendedAction,
    isBlocklisted,
    isAllowlisted,
    breakdown,
    threatIntelStatus
  }) {
    return {
      eventId,
      timestamp,
      domain,
      url,
      riskScore: score,
      riskCategory: tier.name,
      severity: tier.severity,
      color: tier.color,
      confidence,
      detectionIndicators: indicators,
      indicators, // backward compat
      reasons,
      recommendedAction,
      isBlocklisted,
      isAllowlisted,
      breakdown,
      scanSource: 'local_heuristic_engine',
      threatIntelligenceStatus: threatIntelStatus || 'local_heuristic_evaluation',

      // AI-Ready agent integration hooks (extensible for SentinelX backend)
      agentDispatches: {
        orchestratorAgent: { ready: true, status: 'dispatched_local' },
        urlIntelligenceAgent: { ready: true, status: 'evaluated' },
        phishingAnalysisAgent: { ready: true, status: 'evaluated' },
        threatIntelligenceAgent: { ready: true, status: 'pending_api_integration' },
        riskAssessmentAgent: { ready: true, status: 'scored' },
        digitalForensicsAgent: { ready: true, status: 'logged' },
        responseAgent: { ready: true, status: tier.severity === 'critical' ? 'alert_recommended' : 'pass' },
        securityAuditorAgent: { ready: true, status: 'verified_local' }
      }
    };
  }
};

