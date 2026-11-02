/**
 * SentinelX – Redirect Monitor
 * Observes navigation transitions, tracks redirect chains, and identifies suspicious multi-hop hops.
 */

import { parseDomainStructure } from './domain-analyzer.js';

export class RedirectMonitor {
  constructor() {
    // Map of tabId -> redirect chain state
    this.tabChains = new Map();
  }

  /**
   * Reset / initialize chain tracking for a tab
   */
  startNavigation(tabId, url) {
    if (!url || url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:')) {
      return;
    }

    const structure = parseDomainStructure(this.safeGetHostname(url));
    this.tabChains.set(tabId, {
      tabId,
      initialUrl: url,
      initialDomain: structure.rootDomain,
      hops: [{
        url,
        domain: structure.rootDomain,
        timestamp: Date.now()
      }],
      finalUrl: url,
      finalDomain: structure.rootDomain,
      completed: false
    });
  }

  /**
   * Record a hop in the tab's navigation chain
   */
  recordHop(tabId, nextUrl, statusCode = null) {
    if (!nextUrl || nextUrl.startsWith('chrome://') || nextUrl.startsWith('about:')) {
      return;
    }

    let chain = this.tabChains.get(tabId);
    if (!chain) {
      this.startNavigation(tabId, nextUrl);
      chain = this.tabChains.get(tabId);
    }

    const structure = parseDomainStructure(this.safeGetHostname(nextUrl));

    // Don't duplicate if identical to last hop
    const lastHop = chain.hops[chain.hops.length - 1];
    if (lastHop && lastHop.url === nextUrl) {
      return;
    }

    chain.hops.push({
      url: nextUrl,
      domain: structure.rootDomain,
      statusCode,
      timestamp: Date.now()
    });

    chain.finalUrl = nextUrl;
    chain.finalDomain = structure.rootDomain;
  }

  /**
   * Mark navigation as completed
   */
  completeNavigation(tabId, finalUrl) {
    const chain = this.tabChains.get(tabId);
    if (chain) {
      if (finalUrl) {
        chain.finalUrl = finalUrl;
        chain.finalDomain = parseDomainStructure(this.safeGetHostname(finalUrl)).rootDomain;
      }
      chain.completed = true;
    }
  }

  /**
   * Clear state when tab closes
   */
  clearTab(tabId) {
    this.tabChains.delete(tabId);
  }

  /**
   * Analyze the redirect chain for suspicious patterns
   */
  analyzeChain(tabId, currentUrl = null) {
    const chain = this.tabChains.get(tabId);
    const indicators = [];
    const reasons = [];

    if (!chain || chain.hops.length <= 1) {
      return {
        chainLength: 1,
        crossDomainCount: 0,
        hops: chain ? chain.hops : (currentUrl ? [{ url: currentUrl, domain: parseDomainStructure(this.safeGetHostname(currentUrl)).rootDomain }] : []),
        indicators,
        reasons
      };
    }

    const hops = chain.hops;
    const chainLength = hops.length;

    // Count distinct domains in chain
    const uniqueDomains = new Set(hops.map(h => h.domain).filter(Boolean));
    const crossDomainCount = uniqueDomains.size - 1;

    // Check 1: Excessive redirects (3 or more redirect hops)
    if (chainLength >= 4) {
      indicators.push({
        id: 'EXCESSIVE_REDIRECT_CHAIN',
        name: `Excessive Redirect Chain (${chainLength} hops)`,
        description: `Navigation traversed ${chainLength} sequential URL redirects, often used by traffic distribution systems (TDS) to evade scanners.`,
        severity: 'moderate',
        weight: 20,
        category: 'redirect'
      });
      reasons.push(`Website required ${chainLength} consecutive redirects to load.`);
    }

    // Check 2: Cross-domain hopping across multiple unrelated domains
    if (crossDomainCount >= 2) {
      indicators.push({
        id: 'CROSS_DOMAIN_REDIRECTS',
        name: `Cross-Domain Redirect Chain (${crossDomainCount} hops)`,
        description: `Navigation bounced across ${crossDomainCount} different domains before reaching the destination.`,
        severity: 'moderate',
        weight: 25,
        category: 'redirect'
      });
      reasons.push(`Redirect chain bounced across multiple independent domains.`);
    }

    // Check 3: Redirect landed on raw IP address
    const finalStructure = parseDomainStructure(this.safeGetHostname(chain.finalUrl));
    if (finalStructure.isIp && chainLength > 1) {
      indicators.push({
        id: 'REDIRECT_TO_IP_ADDRESS',
        name: 'Redirect Landed on Raw IP Host',
        description: 'The redirect chain ultimately resolved to an unmapped IP address rather than a domain name.',
        severity: 'high',
        weight: 35,
        category: 'redirect'
      });
      reasons.push('Redirect navigated from a domain to a raw IP address.');
    }

    return {
      chainLength,
      crossDomainCount,
      initialUrl: chain.initialUrl,
      finalUrl: chain.finalUrl,
      hops,
      indicators,
      reasons
    };
  }

  safeGetHostname(urlStr) {
    try {
      return new URL(urlStr).hostname;
    } catch {
      return '';
    }
  }
}

