/**
 * SentinelX – Real-Time URL Scanner
 * Evaluates protocol security, URL structure, URL length, embedded credentials,
 * URL shorteners, encoding anomalies, and parameter heuristics.
 */

import { parseDomainStructure, DomainAnalyzer, TARGET_BRANDS } from './domain-analyzer.js';

// Common URL shortening services that mask real destination
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'bit.do', 'rb.gy', 'cutt.ly', 'rebrand.ly',
  'shorturl.at', 'bl.ink', 'tiny.cc'
]);

// Suspicious query parameter names often linked to phishing kits, credential exfiltration or open redirects
const SUSPICIOUS_PARAM_NAMES = [
  'redirect', 'redirect_to', 'redirect_url', 'return_url', 'return_to', 'goto',
  'destination', 'next', 'target', 'auth_token', 'session_id', 'account_id',
  'account_verify', 'update_billing', 'verify_account'
];

export const UrlScanner = {
  /**
   * Scans a full URL string and returns comprehensive URL indicators and metrics
   */
  scan(urlStr) {
    const indicators = [];
    let parsed = null;

    if (!urlStr || typeof urlStr !== 'string') {
      return {
        url: urlStr || '',
        valid: false,
        indicators: [],
        metrics: {}
      };
    }

    try {
      parsed = new URL(urlStr);
    } catch {
      return {
        url: urlStr,
        valid: false,
        indicators: [{
          id: 'MALFORMED_URL',
          name: 'Malformed URL Syntax',
          description: 'The supplied URL could not be parsed as a valid web address.',
          severity: 'moderate',
          weight: 20,
          category: 'url_structure'
        }],
        metrics: {}
      };
    }

    // 1. Protocol Check (HTTP vs HTTPS)
    const protocol = parsed.protocol.toLowerCase();
    if (protocol === 'http:') {
      indicators.push({
        id: 'INSECURE_HTTP_PROTOCOL',
        name: 'Insecure Protocol (HTTP)',
        description: 'Connection is unencrypted (HTTP). Transmitted data is vulnerable to interception and tampering.',
        severity: 'moderate',
        weight: 20,
        category: 'protocol'
      });
    }

    // 2. Embedded Credentials / Userinfo (@ symbol in authority)
    if (parsed.username || parsed.password || urlStr.includes('@')) {
      indicators.push({
        id: 'EMBEDDED_CREDENTIALS_URL',
        name: 'Embedded Credentials Pattern (@)',
        description: 'URL contains an @ symbol before the hostname, a classic technique used in phishing to spoof target domains.',
        severity: 'critical',
        weight: 45,
        category: 'url_structure'
      });
    }

    // 3. Domain Analysis Integration
    const domainAnalysis = DomainAnalyzer.analyze(parsed.hostname);
    indicators.push(...domainAnalysis.indicators);

    // 4. URL Shortener Detection
    const rootDomain = domainAnalysis.structure.rootDomain.toLowerCase();
    if (URL_SHORTENERS.has(rootDomain) || URL_SHORTENERS.has(parsed.hostname.toLowerCase())) {
      indicators.push({
        id: 'URL_SHORTENER_DETECTED',
        name: 'URL Shortening Service Used',
        description: 'The URL uses a known link shortener, which conceals the ultimate landing destination.',
        severity: 'low',
        weight: 15,
        category: 'url_structure'
      });
    }

    // 5. URL Length Analysis
    const totalLength = urlStr.length;
    const pathLength = parsed.pathname.length;
    const queryLength = parsed.search.length;

    if (totalLength > 150) {
      indicators.push({
        id: 'EXCESSIVE_URL_LENGTH',
        name: 'Unusually Long URL',
        description: `URL is ${totalLength} characters long, often used in phishing attacks to pad URLs and hide the true domain in mobile/narrow viewports.`,
        severity: totalLength > 250 ? 'moderate' : 'low',
        weight: totalLength > 250 ? 20 : 10,
        category: 'url_structure'
      });
    }

    // 6. Suspicious characters & Hex Encoding in Path/Query
    if (/%00/i.test(urlStr)) {
      indicators.push({
        id: 'NULL_BYTE_INJECTION',
        name: 'Null Byte Character in URL',
        description: 'URL contains an encoded null byte (%00), frequently associated with path truncation and exploit attempts.',
        severity: 'critical',
        weight: 40,
        category: 'url_structure'
      });
    }

    const encodedMatches = (urlStr.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (encodedMatches >= 8) {
      indicators.push({
        id: 'EXCESSIVE_HEX_ENCODING',
        name: 'Excessive Character Encoding',
        description: 'URL contains multiple hex-encoded characters, potentially attempting to bypass basic signature filters.',
        severity: 'low',
        weight: 10,
        category: 'url_structure'
      });
    }

    // 7. Non-standard ports
    if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
      const portNum = parseInt(parsed.port, 10);
      if ([8080, 8888, 3000, 4444, 8000, 8443, 9000, 1337].includes(portNum)) {
        indicators.push({
          id: 'NON_STANDARD_PORT',
          name: `Non-Standard Port (${portNum})`,
          description: `Website runs on non-standard port ${portNum}, commonly seen in ephemeral staging servers or test phishing kits.`,
          severity: 'moderate',
          weight: 15,
          category: 'protocol'
        });
      }
    }

    // 8. Misleading Subdomain Brand Stuffing
    // e.g. subdomain is "paypal.com" or "apple.com" while rootDomain is "attacker.net"
    if (domainAnalysis.structure.subdomains.length > 0) {
      const subFull = domainAnalysis.structure.subdomains.join('.');
      for (const brand of TARGET_BRANDS) {
        if (subFull.includes(brand) && !rootDomain.includes(brand)) {
          indicators.push({
            id: 'BRAND_IN_SUBDOMAIN',
            name: `Brand Name in Subdomain (${brand})`,
            description: `The known brand "${brand}" is present in the subdomain, while the actual domain is "${rootDomain}".`,
            severity: 'high',
            weight: 35,
            category: 'url_structure'
          });
          break;
        }
      }
    }

    // 9. Suspicious Open Redirect / Sensitive Query Parameters
    const searchParams = parsed.searchParams;
    let foundSuspiciousParam = false;
    let openRedirectCandidate = false;

    for (const [key, value] of searchParams.entries()) {
      const keyLower = key.toLowerCase();
      if (SUSPICIOUS_PARAM_NAMES.includes(keyLower)) {
        foundSuspiciousParam = true;
        // Check if value looks like an external URL
        if (/^https?:\/\//i.test(value)) {
          try {
            const destUrl = new URL(value);
            if (destUrl.hostname.toLowerCase() !== parsed.hostname.toLowerCase()) {
              openRedirectCandidate = true;
            }
          } catch {
            // invalid url in param
          }
        }
      }
    }

    if (openRedirectCandidate) {
      indicators.push({
        id: 'SUSPICIOUS_OPEN_REDIRECT_PARAM',
        name: 'Potential Open Redirect Target in URL',
        description: 'URL query parameter points to an external destination, a common tactic used to bounce users to phishing sites.',
        severity: 'moderate',
        weight: 20,
        category: 'url_structure'
      });
    } else if (foundSuspiciousParam && queryLength > 80) {
      indicators.push({
        id: 'SUSPICIOUS_QUERY_PARAMETERS',
        name: 'Suspicious Security-Related URL Parameters',
        description: 'URL contains sensitive authentication/account-verification query parameters.',
        severity: 'low',
        weight: 10,
        category: 'url_structure'
      });
    }

    return {
      url: urlStr,
      valid: true,
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      domainStructure: domainAnalysis.structure,
      isKnownSafe: domainAnalysis.isKnownSafe,
      indicators,
      metrics: {
        totalLength,
        pathLength,
        queryLength,
        subdomainCount: domainAnalysis.structure.subdomainCount,
        isIp: domainAnalysis.structure.isIp,
        hasPort: !!parsed.port
      }
    };
  }
};

