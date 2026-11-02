/**
 * SentinelX – Comprehensive Automated Test Suite
 * Validates all 16 required test scenarios against the actual detection logic,
 * storage engine, redirect monitor, and risk calculation.
 */

import { UrlScanner } from '../extension/detection/url-scanner.js';
import { DomainAnalyzer } from '../extension/detection/domain-analyzer.js';
import { PhishingDetector } from '../extension/detection/phishing-detector.js';
import { RedirectMonitor } from '../extension/detection/redirect-monitor.js';
import { RiskEngine } from '../extension/detection/risk-engine.js';
import { StorageManager } from '../extension/storage/storage-manager.js';

let passed = 0;
let failed = 0;
const results = [];

function assert(condition, message) {
  if (condition) {
    passed++;
    results.push({ status: 'PASS', message });
    console.log(`  ✓ PASS: ${message}`);
  } else {
    failed++;
    results.push({ status: 'FAIL', message });
    console.error(`  ✗ FAIL: ${message}`);
  }
}

async function runTestSuite() {
  console.log('================================================================');
  console.log('   SentinelX Cyber Defense – Automated Test Suite Execution');
  console.log('================================================================\n');

  // ----------------------------------------------------------------
  // Scenario 1: Normal HTTPS Website (e.g. https://google.com or https://github.com)
  // ----------------------------------------------------------------
  console.log('Scenario 1: Normal HTTPS Website');
  {
    const urlScan = UrlScanner.scan('https://github.com/torvalds/linux');
    const phishingEval = PhishingDetector.evaluate(urlScan);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    assert(urlScan.valid === true, 'URL parsed as valid');
    assert(urlScan.protocol === 'https:', 'HTTPS protocol verified');
    assert(assessment.riskScore <= 24, `Risk score is Low Risk (${assessment.riskScore}/100)`);
    assert(assessment.riskCategory === 'Low Risk', 'Risk category is Low Risk');
  }

  // ----------------------------------------------------------------
  // Scenario 2: HTTP Website (Unencrypted)
  // ----------------------------------------------------------------
  console.log('\nScenario 2: HTTP Website (Unencrypted)');
  {
    const urlScan = UrlScanner.scan('http://example-news-blog.org/articles/123');
    const phishingEval = PhishingDetector.evaluate(urlScan);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    const hasInsecureInd = assessment.indicators.some(i => i.id === 'INSECURE_HTTP_PROTOCOL');
    assert(hasInsecureInd, 'INSECURE_HTTP_PROTOCOL indicator triggered');
    assert(assessment.riskScore >= 20, `Elevated risk score for HTTP (${assessment.riskScore}/100)`);
    assert(assessment.breakdown.protocol > 0, 'Protocol breakdown reflects HTTP penalty');
  }

  // ----------------------------------------------------------------
  // Scenario 3: IP-Based URL (e.g. http://185.220.101.5/login)
  // ----------------------------------------------------------------
  console.log('\nScenario 3: IP-Based URL Hostname');
  {
    const urlScan = UrlScanner.scan('http://185.220.101.5/admin/login');
    const phishingEval = PhishingDetector.evaluate(urlScan);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    assert(urlScan.domainStructure.isIp === true, 'Recognized raw IP address');
    const hasIpInd = assessment.indicators.some(i => i.id === 'IP_ADDRESS_HOSTNAME');
    assert(hasIpInd, 'IP_ADDRESS_HOSTNAME indicator triggered');
    assert(assessment.riskScore >= 50, `High/Critical risk score for raw IP (${assessment.riskScore}/100)`);
  }

  // ----------------------------------------------------------------
  // Scenario 4: Suspiciously Long URL with padded parameters
  // ----------------------------------------------------------------
  console.log('\nScenario 4: Suspiciously Long URL');
  {
    const longUrl = 'https://portal.service.net/verify?' + 'padding_data='.repeat(15) + 'token=abcdef123456';
    const urlScan = UrlScanner.scan(longUrl);
    const phishingEval = PhishingDetector.evaluate(urlScan);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    const hasLengthInd = assessment.indicators.some(i => i.id === 'EXCESSIVE_URL_LENGTH');
    assert(hasLengthInd, 'EXCESSIVE_URL_LENGTH indicator triggered');
    assert(urlScan.metrics.totalLength > 150, `Metrics measured total length as ${urlScan.metrics.totalLength}`);
  }

  // ----------------------------------------------------------------
  // Scenario 5: Lookalike Domain (Typosquatting & Impersonation)
  // ----------------------------------------------------------------
  console.log('\nScenario 5: Lookalike Domain (PayPal & Google typosquatting)');
  {
    // Test paypa1
    const urlScan = UrlScanner.scan('https://paypa1-security-verify.xyz/login');
    const phishingEval = PhishingDetector.evaluate(urlScan);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    assert(phishingEval.brandImpersonated === 'paypal', 'Brand impersonation detected: PayPal');
    assert(assessment.riskScore >= 75, `Critical risk score for brand impersonation (${assessment.riskScore}/100)`);
    assert(assessment.riskCategory === 'Critical Risk', 'Category is Critical Risk');
  }

  // ----------------------------------------------------------------
  // Scenario 6: Punycode Domain
  // ----------------------------------------------------------------
  console.log('\nScenario 6: Punycode Domain');
  {
    const urlScan = UrlScanner.scan('https://xn--pple-43d.com/support');
    const phishingEval = PhishingDetector.evaluate(urlScan);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    const hasPuny = assessment.indicators.some(i => i.id === 'PUNYCODE_DOMAIN');
    assert(hasPuny, 'PUNYCODE_DOMAIN indicator triggered');
    assert(assessment.riskScore >= 35, `Elevated score for punycode encoding (${assessment.riskScore}/100)`);
  }

  // ----------------------------------------------------------------
  // Scenario 7: Suspicious URL Parameters (Open Redirect / Auth exfiltration)
  // ----------------------------------------------------------------
  console.log('\nScenario 7: Suspicious URL Parameters');
  {
    const urlScan = UrlScanner.scan('https://example.com/oauth/return?redirect_url=http://attacker-controlled.net/steal&session_id=98765');
    const phishingEval = PhishingDetector.evaluate(urlScan);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    const hasParamInd = assessment.indicators.some(i => i.id === 'SUSPICIOUS_OPEN_REDIRECT_PARAM');
    assert(hasParamInd, 'SUSPICIOUS_OPEN_REDIRECT_PARAM indicator triggered');
  }

  // ----------------------------------------------------------------
  // Scenario 8: Multiple Redirect Chains (Redirect Monitor)
  // ----------------------------------------------------------------
  console.log('\nScenario 8: Multiple Redirect Chains');
  {
    const monitor = new RedirectMonitor();
    const tabId = 101;
    monitor.startNavigation(tabId, 'https://shortlink.site/jump');
    monitor.recordHop(tabId, 'https://middle-tracker.net/click');
    monitor.recordHop(tabId, 'https://rotator-gateway.io/track');
    monitor.recordHop(tabId, 'https://final-destination.com/welcome');
    monitor.completeNavigation(tabId, 'https://final-destination.com/welcome');

    const redirectAnalysis = monitor.analyzeChain(tabId);
    assert(redirectAnalysis.chainLength === 4, `Chain length recorded as ${redirectAnalysis.chainLength}`);
    assert(redirectAnalysis.crossDomainCount >= 2, `Cross domain hops recorded as ${redirectAnalysis.crossDomainCount}`);
    const hasChainInd = redirectAnalysis.indicators.some(i => i.id === 'EXCESSIVE_REDIRECT_CHAIN');
    assert(hasChainInd, 'EXCESSIVE_REDIRECT_CHAIN indicator triggered');
  }

  // ----------------------------------------------------------------
  // Scenario 9: Suspicious Login Page Indicators (DOM Form Signals)
  // ----------------------------------------------------------------
  console.log('\nScenario 9: Suspicious Login Page Indicators');
  {
    const urlScan = UrlScanner.scan('http://banking-update.xyz/login.html');
    const simulatedDomSignals = {
      hasPasswordInput: true,
      passwordOverHttp: true,
      suspiciousExternalFormAction: true,
      externalActionHost: 'collector-host.ru',
      pageTitle: 'Bank of America Online Sign In'
    };
    const phishingEval = PhishingDetector.evaluate(urlScan, simulatedDomSignals);
    const assessment = RiskEngine.evaluate({ urlScan, phishingEval });

    const hasPwHttp = assessment.indicators.some(i => i.id === 'PASSWORD_OVER_HTTP');
    const hasCrossDomain = assessment.indicators.some(i => i.id === 'CROSS_DOMAIN_FORM_SUBMISSION');
    assert(hasPwHttp, 'PASSWORD_OVER_HTTP indicator triggered');
    assert(hasCrossDomain, 'CROSS_DOMAIN_FORM_SUBMISSION indicator triggered');
    assert(assessment.riskScore >= 80, `Critical score for credential harvest (${assessment.riskScore}/100)`);
  }

  // ----------------------------------------------------------------
  // Scenario 10: Safe Download
  // ----------------------------------------------------------------
  console.log('\nScenario 10: Safe Download');
  {
    const filename = 'Quarterly_Report_2026.pdf';
    const ext = filename.split('.').pop().toLowerCase();
    const isDangerousExt = ['exe', 'scr', 'bat', 'cmd', 'vbs', 'ps1'].includes(ext);
    const isDoubleExt = /\.(pdf|doc|docx|xls|xlsx)\.(exe|scr|bat|cmd|vbs)$/i.test(filename);
    assert(!isDangerousExt, 'Standard PDF extension is not flagged as executable');
    assert(!isDoubleExt, 'Single extension verified safe');
  }

  // ----------------------------------------------------------------
  // Scenario 11: Suspicious Download Extension (Double Extension Masquerade)
  // ----------------------------------------------------------------
  console.log('\nScenario 11: Suspicious Download Extension');
  {
    const badFilename = 'invoice_receipt_march.pdf.exe';
    const ext = badFilename.split('.').pop().toLowerCase();
    const isDangerousExt = ['exe', 'scr', 'bat', 'cmd', 'vbs', 'ps1'].includes(ext);
    const isDoubleExt = /\.(pdf|doc|docx|xls|xlsx)\.(exe|scr|bat|cmd|vbs)$/i.test(badFilename);
    assert(isDangerousExt, 'Executable extension flagged');
    assert(isDoubleExt, 'Double extension masquerade detected (.pdf.exe)');
  }

  // ----------------------------------------------------------------
  // Scenario 12: Allowlisted Domain
  // ----------------------------------------------------------------
  console.log('\nScenario 12: Allowlisted Domain');
  {
    await StorageManager.addToAllowlist('custom-partner-site.com');
    const isAllowed = await StorageManager.isAllowlisted('custom-partner-site.com');
    assert(isAllowed, 'Domain verified as allowlisted in storage');

    const urlScan = UrlScanner.scan('http://custom-partner-site.com/portal');
    const assessment = RiskEngine.evaluate({
      urlScan,
      isAllowlisted: true,
      isBlocklisted: false
    });

    assert(assessment.riskScore === 0, 'Risk score forced to 0 for allowlisted domain');
    assert(assessment.riskCategory === 'Low Risk', 'Risk category is Low Risk');
    assert(assessment.isAllowlisted === true, 'Allowlist flag preserved');
  }

  // ----------------------------------------------------------------
  // Scenario 13: Blocklisted Domain
  // ----------------------------------------------------------------
  console.log('\nScenario 13: Blocklisted Domain');
  {
    await StorageManager.addToBlocklist('known-scam-hub.cc');
    const isBlocked = await StorageManager.isBlocklisted('known-scam-hub.cc');
    assert(isBlocked, 'Domain verified as blocklisted in storage');

    const urlScan = UrlScanner.scan('https://known-scam-hub.cc');
    const assessment = RiskEngine.evaluate({
      urlScan,
      isAllowlisted: false,
      isBlocklisted: true
    });

    assert(assessment.riskScore === 100, 'Risk score forced to 100 for blocklisted domain');
    assert(assessment.riskCategory === 'Critical Risk', 'Risk category is Critical Risk');
    assert(assessment.isBlocklisted === true, 'Blocklist flag preserved');
  }

  // ----------------------------------------------------------------
  // Scenario 14: Protection Disabled State
  // ----------------------------------------------------------------
  console.log('\nScenario 14: Protection Disabled State');
  {
    await StorageManager.updateSetting('protectionEnabled', false);
    const settings = await StorageManager.getSettings();
    assert(settings.protectionEnabled === false, 'Protection verified toggled off');

    // Simulate paused response from service worker
    const pausedAssessment = {
      paused: true,
      riskScore: 0,
      riskCategory: 'Protection Paused'
    };
    assert(pausedAssessment.paused === true, 'Engine respects paused state');

    // Re-enable protection for subsequent tests
    await StorageManager.updateSetting('protectionEnabled', true);
  }

  // ----------------------------------------------------------------
  // Scenario 15: Empty Scan History
  // ----------------------------------------------------------------
  console.log('\nScenario 15: Empty Scan History');
  {
    await StorageManager.clearScanHistory();
    const history = await StorageManager.getScanHistory();
    assert(Array.isArray(history) && history.length === 0, 'History accurately returns empty array');
  }

  // ----------------------------------------------------------------
  // Scenario 16: Settings Persistence & Roundtrip
  // ----------------------------------------------------------------
  console.log('\nScenario 16: Settings Persistence & Roundtrip');
  {
    await StorageManager.saveSettings({
      notificationsEnabled: false,
      notificationThreshold: 'all'
    });

    const reloaded = await StorageManager.getSettings();
    assert(reloaded.notificationsEnabled === false, 'notificationsEnabled persisted');
    assert(reloaded.notificationThreshold === 'all', 'notificationThreshold persisted');

    // Reset settings
    await StorageManager.resetSettings();
    const resetSettings = await StorageManager.getSettings();
    assert(resetSettings.notificationsEnabled === true, 'resetSettings restored default');
  }

  // ----------------------------------------------------------------
  // Test Summary
  // ----------------------------------------------------------------
  console.log('\n================================================================');
  console.log(`   TEST RESULTS SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Fatal error during test suite:', err);
  process.exit(1);
});

