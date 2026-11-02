/**
 * SentinelX – Domain Intelligence Analyzer
 * Analyzes domain structure, subdomains, IP addresses, punycode, homoglyphs, and known domain reputations.
 */

// Common multi-part public suffixes
const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.jp', 'ne.jp', 'ac.jp',
  'co.nz', 'net.nz', 'org.nz',
  'com.br', 'gov.br',
  'com.cn', 'net.cn', 'gov.cn',
  'co.in', 'net.in', 'org.in', 'gen.in',
  'com.sg', 'edu.sg',
  'com.tw', 'org.tw',
  'com.tr', 'edu.tr'
]);

// Suspicious / high-abuse TLDs frequently abused in automated phishing campaigns
const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', // Freenom free TLDs historically heavily abused
  'xyz', 'top', 'buzz', 'club', 'work', 'country', 'click', 'link',
  'stream', 'rest', 'icu', 'cam', 'monster', 'sbs', 'cfd', 'quest',
  'lat', 'men', 'loan', 'racing', 'win', 'bid', 'review'
]);

// Top legitimate domains (known-safe baseline)
const KNOWN_SAFE_DOMAINS = new Set([
  'google.com', 'google.co.uk', 'google.ca', 'google.de', 'google.fr', 'google.co.in',
  'youtube.com', 'microsoft.com', 'apple.com', 'github.com', 'wikipedia.org',
  'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in',
  'netflix.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'linkedin.com', 'cloudflare.com', 'mozilla.org', 'stackoverflow.com',
  'reddit.com', 'yahoo.com', 'bing.com', 'duckduckgo.com', 'dropbox.com',
  'slack.com', 'zoom.us', 'notion.so', 'figma.com', 'openai.com', 'anthropic.com'
]);

// High-value targets for brand impersonation
export const TARGET_BRANDS = [
  'google', 'microsoft', 'apple', 'paypal', 'amazon', 'netflix', 'facebook',
  'instagram', 'linkedin', 'twitter', 'chase', 'bankofamerica', 'wellsfargo',
  'citi', 'binance', 'coinbase', 'metamask', 'dhl', 'fedex', 'usps',
  'dropbox', 'adobe', 'walmart', 'ebay', 'spotify', 'steam', 'whatsapp', 'telegram'
];

// Common Cyrillic / Greek homoglyph mappings to Latin
const HOMOGLYPH_MAP = {
  '\u0430': 'a', // Cyrillic small letter a
  '\u0435': 'e', // Cyrillic small letter ie
  '\u043E': 'o', // Cyrillic small letter o
  '\u0440': 'p', // Cyrillic small letter er
  '\u0441': 'c', // Cyrillic small letter es
  '\u0443': 'y', // Cyrillic small letter u
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
  '\u0458': 'j', // Cyrillic small letter je
  '\u0455': 's', // Cyrillic small letter dze
  '\u03B1': 'a', // Greek small letter alpha
  '\u03BF': 'o', // Greek small letter omicron
  '\u03C1': 'p', // Greek small letter rho
  '\u03BD': 'v'  // Greek small letter nu
};

/**
 * Check if string is an IPv4 or IPv6 address
 */
export function isIpAddress(hostname) {
  if (!hostname) return false;
  // Strip brackets for IPv6
  const clean = hostname.replace(/^\[|\]$/g, '');

  // IPv4 standard regex
  const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Pattern.test(clean)) return true;

  // IPv4 hex / octal / decimal representations (e.g. 0x7f000001 or 2130706433)
  if (/^0x[0-9a-fA-F]+$/.test(clean) || /^\d{8,11}$/.test(clean)) return true;

  // IPv6 pattern
  const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Pattern.test(clean);
}

/**
 * Deconstruct hostname into subdomains, root domain, and TLD
 */
export function parseDomainStructure(hostname) {
  if (!hostname) {
    return {
      hostname: '',
      isIp: false,
      subdomains: [],
      rootDomain: '',
      tld: '',
      subdomainCount: 0
    };
  }

  const cleanHost = hostname.toLowerCase().trim().replace(/^\[|\]$/g, '');

  if (isIpAddress(cleanHost)) {
    return {
      hostname: cleanHost,
      isIp: true,
      subdomains: [],
      rootDomain: cleanHost,
      tld: 'IP',
      subdomainCount: 0
    };
  }

  const parts = cleanHost.split('.');
  if (parts.length <= 1) {
    return {
      hostname: cleanHost,
      isIp: false,
      subdomains: [],
      rootDomain: cleanHost,
      tld: '',
      subdomainCount: 0
    };
  }

  // Check for multi-part TLD (e.g. .co.uk)
  let tld = parts[parts.length - 1];
  let rootDomain = '';
  let subdomains = [];

  if (parts.length >= 3) {
    const candidateMulti = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (MULTI_PART_TLDS.has(candidateMulti)) {
      tld = candidateMulti;
      rootDomain = `${parts[parts.length - 3]}.${candidateMulti}`;
      subdomains = parts.slice(0, parts.length - 3);
      return {
        hostname: cleanHost,
        isIp: false,
        subdomains,
        rootDomain,
        tld,
        subdomainCount: subdomains.length
      };
    }
  }

  // Standard single TLD
  tld = parts[parts.length - 1];
  rootDomain = `${parts[parts.length - 2]}.${tld}`;
  subdomains = parts.slice(0, parts.length - 2);

  return {
    hostname: cleanHost,
    isIp: false,
    subdomains,
    rootDomain,
    tld,
    subdomainCount: subdomains.length
  };
}

/**
 * Detect punycode and homoglyph attacks
 */
export function analyzePunycodeAndHomoglyphs(hostname) {
  const indicators = [];
  if (!hostname) return { isPunycode: false, hasHomoglyphs: false, indicators };

  const isPunycode = hostname.toLowerCase().includes('xn--');
  if (isPunycode) {
    indicators.push({
      id: 'PUNYCODE_DOMAIN',
      name: 'Punycode Encoded Domain',
      description: 'The domain uses Punycode (xn--) encoding, often used to disguise lookalike characters.',
      severity: 'high',
      weight: 35,
      category: 'domain_intelligence'
    });
  }

  // Check for homoglyph characters in unicode hostname
  let foundHomoglyphs = [];
  for (let i = 0; i < hostname.length; i++) {
    const char = hostname[i];
    if (HOMOGLYPH_MAP[char]) {
      foundHomoglyphs.push({ char, asciiEquivalent: HOMOGLYPH_MAP[char] });
    }
  }

  if (foundHomoglyphs.length > 0) {
    indicators.push({
      id: 'HOMOGLYPH_CHARACTERS',
      name: 'Homoglyph Characters Detected',
      description: `Domain contains non-Latin lookalike characters resembling Latin letters (${foundHomoglyphs.map(h => h.char + '->' + h.asciiEquivalent).join(', ')}).`,
      severity: 'critical',
      weight: 45,
      category: 'domain_intelligence'
    });
  }

  return {
    isPunycode,
    hasHomoglyphs: foundHomoglyphs.length > 0,
    homoglyphs: foundHomoglyphs,
    indicators
  };
}

/**
 * Standard Levenshtein Distance for string similarity
 */
export function levenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Domain Analyzer main evaluation
 */
export const DomainAnalyzer = {
  analyze(hostname) {
    const structure = parseDomainStructure(hostname);
    const punycodeAnalysis = analyzePunycodeAndHomoglyphs(structure.hostname);
    const indicators = [...punycodeAnalysis.indicators];

    // Check IP address usage
    if (structure.isIp) {
      indicators.push({
        id: 'IP_ADDRESS_HOSTNAME',
        name: 'Direct IP Address Hostname',
        description: 'The website uses a raw IP address instead of a standard domain name, frequently associated with malicious staging or phishing.',
        severity: 'high',
        weight: 35,
        category: 'domain_intelligence'
      });
    }

    // Check excessive subdomains
    if (structure.subdomainCount >= 3) {
      indicators.push({
        id: 'EXCESSIVE_SUBDOMAINS',
        name: 'Excessive Subdomains',
        description: `Website hostname contains ${structure.subdomainCount} subdomains, which can be used to obfuscate the real destination domain.`,
        severity: structure.subdomainCount >= 4 ? 'moderate' : 'low',
        weight: structure.subdomainCount >= 4 ? 20 : 10,
        category: 'domain_intelligence'
      });
    }

    // Check suspicious TLD
    const tld = structure.tld.toLowerCase();
    if (SUSPICIOUS_TLDS.has(tld)) {
      indicators.push({
        id: 'SUSPICIOUS_TLD',
        name: 'High-Abuse Top-Level Domain',
        description: `The top-level domain (.${tld}) has statistically elevated incidence in automated phishing and cyber attacks.`,
        severity: 'moderate',
        weight: 15,
        category: 'domain_intelligence'
      });
    }

    // Check Known Safe list
    const isKnownSafe = KNOWN_SAFE_DOMAINS.has(structure.rootDomain);

    return {
      structure,
      isKnownSafe,
      indicators,
      threatIntelligenceStatus: 'local_heuristic_evaluation'
    };
  }
};
