/**
 * SentinelX – Phishing Detection Engine
 * Multi-indicator phishing analysis engine evaluating brand impersonation,
 * lookalike domains, typosquatting, login keywords, and DOM-level form signals.
 */

import { TARGET_BRANDS, levenshteinDistance, parseDomainStructure } from './domain-analyzer.js';

// Suspicious security / login keywords frequently present in phishing paths
const LOGIN_PATH_KEYWORDS = [
  'login', 'signin', 'log-in', 'sign-in', 'logon', 'authenticate',
  'auth', 'verification', 'verify', 'account-update', 'security-challenge',
  'webscr', 'cmd=_login', 'wallet', 'confirm', 'banking', 'billing'
];

// Brand official primary domains
const BRAND_OFFICIAL_DOMAINS = {
  'google': ['google.com', 'google.co.uk', 'google.ca', 'google.de', 'google.co.in', 'youtube.com', 'gmail.com'],
  'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'msn.com', 'azure.com'],
  'apple': ['apple.com', 'icloud.com'],
  'paypal': ['paypal.com', 'paypal.me'],
  'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'aws.amazon.com'],
  'netflix': ['netflix.com'],
  'facebook': ['facebook.com', 'fb.com', 'meta.com'],
  'instagram': ['instagram.com'],
  'linkedin': ['linkedin.com'],
  'twitter': ['twitter.com', 'x.com'],
  'chase': ['chase.com', 'jpmorganchase.com'],
  'bankofamerica': ['bankofamerica.com', 'bofa.com'],
  'wellsfargo': ['wellsfargo.com'],
  'citi': ['citi.com', 'citigroup.com', 'citibank.com'],
  'binance': ['binance.com'],
  'coinbase': ['coinbase.com'],
  'metamask': ['metamask.io'],
  'dhl': ['dhl.com'],
  'fedex': ['fedex.com'],
  'usps': ['usps.com'],
  'dropbox': ['dropbox.com'],
  'adobe': ['adobe.com']
};

/**
 * Check if domain is official for a given brand
 */
function isOfficialDomainForBrand(rootDomain, brand) {
  const officialList = BRAND_OFFICIAL_DOMAINS[brand];
  if (!officialList) return false;
  const cleanRoot = rootDomain.toLowerCase();
  return officialList.some(d => cleanRoot === d || cleanRoot.endsWith('.' + d));
}

/**
 * Detect typosquatting variants (e.g., paypa1, micros0ft, arnazon)
 */
function detectTyposquatting(nameWithoutTld, brand) {
  if (!nameWithoutTld || nameWithoutTld === brand) return false;

  // Normalized visual substitutes (check both 1->l for paypal/google, and 1->i for microsoft)
  const normL = nameWithoutTld
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm')
    .replace(/5/g, 's');

  const normI = nameWithoutTld
    .replace(/0/g, 'o')
    .replace(/1/g, 'i')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm')
    .replace(/5/g, 's');

  if (normL === brand || normI === brand) return true;

  // Levenshtein distance: 1 edit for length >= 4, or 2 edits for length >= 7
  const dist = levenshteinDistance(nameWithoutTld, brand);
  if (brand.length >= 4 && dist === 1) return true;
  if (brand.length >= 7 && dist === 2 && !nameWithoutTld.includes(brand)) return true;

  return false;
}

export const PhishingDetector = {
  /**
   * Evaluates phishing indicators using URL data, domain breakdown, and DOM signals
   * @param {Object} urlScanResult - Output from UrlScanner.scan()
   * @param {Object} [domSignals] - Optional DOM characteristics collected by content/page-monitor.js
   */
  evaluate(urlScanResult, domSignals = null) {
    const indicators = [];
    const reasons = [];

    if (!urlScanResult || !urlScanResult.valid) {
      return {
        indicators,
        reasons,
        phishingConfidence: 'None',
        brandImpersonated: null
      };
    }

    const { hostname, pathname, search, domainStructure, isKnownSafe } = urlScanResult;
    const rootDomain = domainStructure.rootDomain.toLowerCase();
    const domainNameWithoutTld = rootDomain.split('.')[0];
    const fullUrlLower = (urlScanResult.url || '').toLowerCase();

    // Skip heavy brand impersonation flags if domain is already verified in known-safe list
    let detectedImpersonatedBrand = null;

    if (!isKnownSafe) {
      // 1. Brand Impersonation & Typosquatting Checks
      for (const brand of TARGET_BRANDS) {
        // Skip if this is the legitimate brand domain
        if (isOfficialDomainForBrand(rootDomain, brand)) {
          continue;
        }

        // A. Direct typosquatting on the root domain name or compound tokens
        const domainTokens = domainNameWithoutTld.split('-');
        const isTyposquat = detectTyposquatting(domainNameWithoutTld, brand) || domainTokens.some(t => detectTyposquatting(t, brand));

        if (isTyposquat) {
          detectedImpersonatedBrand = brand;
          indicators.push({
            id: 'LOOKALIKE_BRAND_DOMAIN',
            name: `Lookalike Domain (${brand.toUpperCase()})`,
            description: `The domain "${rootDomain}" appears to imitate the legitimate brand "${brand}" via character substitution or typosquatting.`,
            severity: 'critical',
            weight: 50,
            category: 'phishing'
          });
          reasons.push(`Domain closely mimics the protected brand "${brand}".`);
          break;
        }

        // B. Hyphenated fake brand compound (e.g. "paypal-security-update.com", "login-apple.xyz")
        const hyphenRegex = new RegExp(`(^|-)${brand}(-|$)`);
        if (hyphenRegex.test(domainNameWithoutTld)) {
          detectedImpersonatedBrand = brand;
          indicators.push({
            id: 'BRAND_NAME_IN_DOMAIN',
            name: `Brand Impersonation in Domain (${brand.toUpperCase()})`,
            description: `The domain contains the brand keyword "${brand}" combined with extra words or hyphens, typical of phishing infrastructure.`,
            severity: 'high',
            weight: 40,
            category: 'phishing'
          });
          reasons.push(`Domain contains the brand name "${brand}" on an unofficial domain.`);
          break;
        }
      }
    }

    // 2. Suspicious Login Page Indicators in URL
    const hasLoginKeywordInUrl = LOGIN_PATH_KEYWORDS.some(kw => 
      pathname.toLowerCase().includes(kw) || search.toLowerCase().includes(kw)
    );

    if (hasLoginKeywordInUrl) {
      // If combined with brand impersonation or suspicious TLD or IP, flag with higher weight
      if (detectedImpersonatedBrand || domainStructure.isIp || indicators.some(i => i.severity === 'high' || i.severity === 'critical')) {
        indicators.push({
          id: 'SUSPICIOUS_LOGIN_TARGET',
          name: 'Deceptive Authentication Endpoint',
          description: 'The page presents authentication / login paths on an unverified or impersonated domain.',
          severity: 'high',
          weight: 35,
          category: 'phishing'
        });
        reasons.push('Authentication or credential collection path hosted on an untrusted domain.');
      } else if (!isKnownSafe) {
        indicators.push({
          id: 'LOGIN_PATH_UNVERIFIED_DOMAIN',
          name: 'Login Form on Unverified Domain',
          description: 'Login-related path keywords detected. Exercise caution before entering credentials.',
          severity: 'low',
          weight: 10,
          category: 'phishing'
        });
      }
    }

    // 3. Page DOM Signals (from content/page-monitor.js)
    if (domSignals) {
      // Password field over plain HTTP
      if (domSignals.passwordOverHttp) {
        indicators.push({
          id: 'PASSWORD_OVER_HTTP',
          name: 'Password Input Over Insecure Connection',
          description: 'The page requests passwords over unencrypted HTTP, leaving credentials exposed in transit.',
          severity: 'critical',
          weight: 50,
          category: 'phishing'
        });
        reasons.push('Password requested over insecure unencrypted protocol.');
      }

      // Password input field on untrusted/impersonated domain
      if (domSignals.hasPasswordInput && (detectedImpersonatedBrand || domainStructure.isIp)) {
        indicators.push({
          id: 'CREDENTIAL_FORM_ON_SUSPICIOUS_DOMAIN',
          name: 'Credential Harvest Form Detected',
          description: 'Password input field detected on an IP address or impersonated domain.',
          severity: 'critical',
          weight: 45,
          category: 'phishing'
        });
        reasons.push('Password input detected on a high-risk or lookalike domain.');
      }

      // Suspicious External Form Action (exfiltration vector)
      if (domSignals.suspiciousExternalFormAction) {
        indicators.push({
          id: 'CROSS_DOMAIN_FORM_SUBMISSION',
          name: 'Suspicious External Form Destination',
          description: `Form data is submitted to an unrelated external domain (${domSignals.externalActionHost || 'external'}), a hallmark of credential harvesting kits.`,
          severity: 'high',
          weight: 35,
          category: 'phishing'
        });
        reasons.push('Page form submits sensitive data to an external third-party destination.');
      }

      // Form Action is a Raw IP
      if (domSignals.formActionIsIp) {
        indicators.push({
          id: 'FORM_ACTION_RAW_IP',
          name: 'Form Posts to Raw IP Address',
          description: 'Form submission destination is a direct IP address rather than a recognized domain.',
          severity: 'critical',
          weight: 40,
          category: 'phishing'
        });
        reasons.push('Form data targets a raw IP address.');
      }

      // Brand Spoofing in Page Title
      if (domSignals.pageTitle && !isKnownSafe) {
        const titleLower = domSignals.pageTitle.toLowerCase();
        for (const brand of TARGET_BRANDS) {
          if (titleLower.includes(brand) && !rootDomain.includes(brand) && !isOfficialDomainForBrand(rootDomain, brand)) {
            indicators.push({
              id: 'TITLE_BRAND_MISMATCH',
              name: `Brand Name in Page Title Mismatch (${brand.toUpperCase()})`,
              description: `The webpage title claims to be "${brand}", but the actual hosting domain is "${rootDomain}".`,
              severity: 'high',
              weight: 35,
              category: 'phishing'
            });
            reasons.push(`Page title claims "${brand}" affiliation while domain is "${rootDomain}".`);
            break;
          }
        }
      }
    }

    // Determine Phishing Confidence Level
    let totalPhishingWeight = indicators.reduce((sum, ind) => sum + (ind.weight || 0), 0);
    let phishingConfidence = 'None';

    if (totalPhishingWeight >= 70) {
      phishingConfidence = 'High';
    } else if (totalPhishingWeight >= 35) {
      phishingConfidence = 'Medium';
    } else if (totalPhishingWeight > 0) {
      phishingConfidence = 'Low';
    }

    return {
      indicators,
      reasons,
      phishingConfidence,
      brandImpersonated: detectedImpersonatedBrand,
      totalPhishingWeight
    };
  }
};
