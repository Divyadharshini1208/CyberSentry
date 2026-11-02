/**
 * SentinelX – Background Service Worker (Manifest V3)
 * Orchestrates real-time tab scanning, navigation redirect monitoring,
 * dangerous download inspection, and security notifications.
 */

import { UrlScanner } from '../detection/url-scanner.js';
import { PhishingDetector } from '../detection/phishing-detector.js';
import { RedirectMonitor } from '../detection/redirect-monitor.js';
import { RiskEngine } from '../detection/risk-engine.js';
import { StorageManager } from '../storage/storage-manager.js';
import { notificationManager } from '../notifications/notification-manager.js';

const redirectMonitor = new RedirectMonitor();

// In-memory cache for recent tab evaluations
const activeTabScans = new Map();

// High-risk executable extensions
const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'scr', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
  'ps1', 'ps1xml', 'ps2', 'msi', 'msp', 'dll', 'hta', 'cpl', 'jar',
  'iso', 'img', 'gadget', 'pif', 'com'
]);

// Double extension regex (e.g. invoice.pdf.exe)
const DOUBLE_EXTENSION_REGEX = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|zip|tar|rar)\.(exe|scr|bat|cmd|vbs|hta|js|ps1|msi|iso)$/i;

/**
 * Update Chrome extension action badge
 */
function updateBadge(tabId, scanResult, protectionEnabled = true) {
  if (typeof chrome === 'undefined' || !chrome.action) return;

  if (!protectionEnabled) {
    chrome.action.setBadgeText({ tabId, text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#6b7280' });
    chrome.action.setTitle({ tabId, title: 'CyberSentry: Protection is paused' });
    return;
  }

  if (!scanResult || scanResult.unsupported) {
    chrome.action.setBadgeText({ tabId, text: '' });
    chrome.action.setTitle({ tabId, title: 'CyberSentry: Internal browser page' });
    return;
  }

  const scoreStr = String(scanResult.riskScore);
  chrome.action.setBadgeText({ tabId, text: scoreStr });

  let badgeColor = '#10b981'; // green
  if (scanResult.riskScore >= 75) {
    badgeColor = '#ef4444'; // red
  } else if (scanResult.riskScore >= 50) {
    badgeColor = '#f97316'; // orange
  } else if (scanResult.riskScore >= 25) {
    badgeColor = '#f59e0b'; // amber
  }

  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  chrome.action.setTitle({
    tabId,
    title: `CyberSentry: ${scanResult.riskCategory} (${scanResult.riskScore}/100) on ${scanResult.domain}`
  });
}

/**
 * Execute full security analysis on a tab
 */
async function scanTab(tabId, url, domSignals = null) {
  if (!url || typeof url !== 'string') return null;

  // Handle browser internal pages
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('edge://') || url.startsWith('about:')) {
    const unsuppResult = {
      unsupported: true,
      url,
      domain: 'browser-internal',
      riskScore: 0,
      riskCategory: 'Low Risk',
      severity: 'low',
      reasons: ['Internal browser page; security scanning is bypassed.'],
      indicators: [],
      recommendedAction: 'Internal browser system page.'
    };
    activeTabScans.set(tabId, unsuppResult);
    updateBadge(tabId, unsuppResult);
    return unsuppResult;
  }

  const settings = await StorageManager.getSettings();

  // If protection is disabled, mark as paused
  if (!settings.protectionEnabled) {
    const pausedResult = {
      paused: true,
      url,
      domain: new URL(url).hostname,
      riskScore: 0,
      riskCategory: 'Protection Paused',
      severity: 'low',
      reasons: ['CyberSentry real-time protection is currently toggled off in settings.'],
      indicators: [],
      recommendedAction: 'Enable protection in CyberSentry settings to activate real-time threat scanning.'
    };
    activeTabScans.set(tabId, pausedResult);
    updateBadge(tabId, pausedResult, false);
    return pausedResult;
  }

  // 1. URL Analysis
  const urlScan = UrlScanner.scan(url);
  const domain = urlScan.domainStructure ? urlScan.domainStructure.rootDomain : urlScan.hostname;

  // 2. Policy checks
  const isAllow = await StorageManager.isAllowlisted(domain);
  const isBlock = await StorageManager.isBlocklisted(domain);

  // 3. Phishing Evaluation
  let phishingEval = null;
  if (settings.phishingDetectionEnabled) {
    phishingEval = PhishingDetector.evaluate(urlScan, domSignals);
  }

  // 4. Redirect Chain Analysis
  const redirectEval = redirectMonitor.analyzeChain(tabId, url);

  // 5. Compute Final Risk Assessment
  const assessment = RiskEngine.evaluate({
    urlScan,
    phishingEval,
    redirectEval,
    isAllowlisted: isAllow,
    isBlocklisted: isBlock
  });

  // Attach metadata
  assessment.tabId = tabId;
  assessment.domSignals = domSignals;
  assessment.redirectDetails = redirectEval;

  // Cache tab scan
  activeTabScans.set(tabId, assessment);
  await StorageManager.setTabScan(tabId, assessment);

  // Record to scan history if auto-scan is enabled
  if (settings.autoScanEnabled && !assessment.unsupported) {
    await StorageManager.addScanHistory(assessment);
  }

  // Update extension badge
  updateBadge(tabId, assessment, settings.protectionEnabled);

  // Send notification if risk meets criteria
  if (assessment.riskScore >= 50 && settings.notificationsEnabled) {
    notificationManager.notifyWebsiteRisk(assessment, settings);
  }

  // Asynchronously enrich with backend threat intelligence and telemetry (non-blocking)
  enrichWithBackend(tabId, assessment, settings);

  return assessment;
}

/**
 * Asynchronously enriches the tab scan with backend threat intelligence, ML, and telemetry
 */
async function enrichWithBackend(tabId, assessment, settings) {
  if (!settings.backendUrl || (!settings.backendEnrichmentEnabled && !settings.telemetryEnabled)) {
    assessment.backendAnalysis = { status: 'offline', message: 'Backend integration is disabled in settings.' };
    return;
  }

  const backendUrl = settings.backendUrl.replace(/\/+$/, '');
  const apiKey = settings.backendApiKey || 'sentinelx-client-dev-key';
  const headers = {
    'Content-Type': 'application/json',
    'X-CyberSentry-Key': apiKey,
    'X-SentinelX-Key': apiKey
  };

  // 1. Backend URL Scan & Threat Intel Enrichment
  if (settings.backendEnrichmentEnabled && !assessment.unsupported && !assessment.paused) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const resp = await fetch(`${backendUrl}/api/v1/scans/url`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          url: assessment.url,
          enableThreatIntel: true,
          enableMl: true,
          clientIdentity: 'browser-extension-client'
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (resp.ok) {
        const json = await resp.json();
        if (json.success && json.data) {
          const bData = json.data;
          assessment.backendAnalysis = {
            status: 'online',
            scanId: bData.scanId,
            threatIntel: bData.threatIntelSummary,
            mlPrediction: bData.mlPrediction,
            completedAt: bData.completedAt
          };

          // If backend detected higher risk (e.g. from VirusTotal/URLhaus), elevate score
          if (bData.riskScore > assessment.riskScore && !assessment.isAllowlisted) {
            assessment.riskScore = bData.riskScore;
            assessment.riskCategory = bData.riskCategory;
            assessment.severity = bData.severity;
            if (bData.reasons) {
              assessment.reasons = Array.from(new Set([...assessment.reasons, ...bData.reasons]));
            }
            updateBadge(tabId, assessment, settings.protectionEnabled);
          }
        }
      } else {
        assessment.backendAnalysis = { status: 'offline', message: `Backend responded with HTTP ${resp.status}` };
      }
    } catch (err) {
      assessment.backendAnalysis = { status: 'offline', message: 'Backend unreachable. Running in autonomous local mode.' };
    }
  } else {
    assessment.backendAnalysis = { status: 'local', message: 'Local heuristic evaluation mode active.' };
  }

  // 2. Telemetry ingestion
  if (settings.telemetryEnabled && !assessment.unsupported && !assessment.paused) {
    try {
      await fetch(`${backendUrl}/api/v1/telemetry/events`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          eventId: assessment.eventId,
          timestamp: assessment.timestamp,
          domain: assessment.domain,
          url: assessment.url,
          riskScore: assessment.riskScore,
          riskCategory: assessment.riskCategory,
          severity: assessment.severity,
          confidence: assessment.confidence,
          detectionIndicators: (assessment.indicators || []).map(i => ({
            id: i.id,
            name: i.name,
            severity: i.severity || 'moderate',
            weight: i.weight || 0,
            scoreContribution: i.scoreContribution || 0,
            description: i.description,
            category: i.category || 'url_structure'
          })),
          agentDispatches: assessment.agentDispatches || {},
          source: 'browser_extension',
          schemaVersion: '1.0'
        })
      });
    } catch {
      // Ignore telemetry failure silently to avoid interfering with user experience
    }
  }

  // Update tab scan cache with backend enrichment
  activeTabScans.set(tabId, assessment);
  await StorageManager.setTabScan(tabId, assessment);
}

/**
 * Scan arbitrary URL on demand (e.g. manual scan tool)
 */
async function scanArbitraryUrl(urlStr) {
  const urlScan = UrlScanner.scan(urlStr);
  const domain = urlScan.domainStructure ? urlScan.domainStructure.rootDomain : (urlScan.hostname || 'unknown');
  const isAllow = await StorageManager.isAllowlisted(domain);
  const isBlock = await StorageManager.isBlocklisted(domain);

  const phishingEval = PhishingDetector.evaluate(urlScan, null);
  const assessment = RiskEngine.evaluate({
    urlScan,
    phishingEval,
    redirectEval: null,
    isAllowlisted: isAllow,
    isBlocklisted: isBlock
  });

  return assessment;
}

/**
 * Download Security Inspector
 */
async function inspectDownload(downloadItem) {
  const settings = await StorageManager.getSettings();
  if (!settings.downloadMonitoringEnabled || !settings.protectionEnabled) return;

  const url = downloadItem.url || downloadItem.finalUrl || '';
  const filename = downloadItem.filename || '';
  const basename = filename.split(/[/\\]/).pop();

  const parts = basename.split('.');
  const ext = (parts.length > 1 ? parts.pop() : '').toLowerCase();

  const isExecutable = DANGEROUS_EXTENSIONS.has(ext);
  const isDoubleExt = DOUBLE_EXTENSION_REGEX.test(basename);
  const isInsecureHttp = url.startsWith('http://');

  let downloadRiskScore = 0;
  const reasons = [];

  if (isDoubleExt) {
    downloadRiskScore += 70;
    reasons.push(`Double extension masquerade detected in filename "${basename}".`);
  } else if (isExecutable) {
    downloadRiskScore += 40;
    reasons.push(`Executable binary download format (.${ext}).`);
  }

  if (isInsecureHttp) {
    downloadRiskScore += 25;
    reasons.push('File downloaded over unencrypted HTTP connection.');
  }

  // If suspicious, notify user
  if (downloadRiskScore >= 40) {
    const severity = downloadRiskScore >= 70 ? 'critical' : 'high';
    notificationManager.notifyDownloadWarning({
      filename: basename,
      riskReason: reasons.join(' '),
      severity
    });

    // Record download event to history
    await StorageManager.addScanHistory({
      eventId: `dl_${Date.now()}`,
      timestamp: new Date().toISOString(),
      domain: new URL(url).hostname,
      url,
      riskScore: downloadRiskScore,
      riskCategory: downloadRiskScore >= 70 ? 'Critical Risk' : 'High Risk',
      severity,
      confidence: 'High',
      indicators: [{
        id: isDoubleExt ? 'DOUBLE_EXTENSION_DOWNLOAD' : 'EXECUTABLE_DOWNLOAD',
        name: isDoubleExt ? 'Double Extension Deception' : 'Executable File Download',
        description: reasons.join(' '),
        severity,
        weight: downloadRiskScore,
        category: 'download'
      }],
      reasons,
      recommendedAction: 'Scan file with antivirus before running.'
    });
  }
}

// -------------------------------------------------------------
// Chrome Event Listeners
// -------------------------------------------------------------

// Navigation tracking for redirects
if (typeof chrome !== 'undefined' && chrome.webNavigation) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
      redirectMonitor.startNavigation(details.tabId, details.url);
    }
  });

  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) {
      redirectMonitor.recordHop(details.tabId, details.url, details.transitionType);
    }
  });

  chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0) {
      redirectMonitor.completeNavigation(details.tabId, details.url);
    }
  });
}

// Tab navigation updates
if (typeof chrome !== 'undefined' && chrome.tabs) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && changeInfo.url) {
      scanTab(tabId, changeInfo.url);
    } else if (changeInfo.status === 'complete' && tab.url) {
      scanTab(tabId, tab.url);
    }
  });

  chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId);
      if (tab && tab.url) {
        let cached = activeTabScans.get(activeInfo.tabId);
        if (!cached) {
          cached = await scanTab(activeInfo.tabId, tab.url);
        }
        const settings = await StorageManager.getSettings();
        updateBadge(activeInfo.tabId, cached, settings.protectionEnabled);
      }
    } catch {
      // Tab might have closed
    }
  });

  chrome.tabs.onRemoved.addListener((tabId) => {
    activeTabScans.delete(tabId);
    redirectMonitor.clearTab(tabId);
    StorageManager.removeTabScan(tabId);
  });
}

// Download monitoring
if (typeof chrome !== 'undefined' && chrome.downloads) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    inspectDownload(downloadItem);
  });
}

// Message Dispatcher
if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.type) return false;

    // Handle asynchronous responses
    (async () => {
      try {
        switch (message.type) {
          case 'GET_ACTIVE_TAB_SCAN': {
            let [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!activeTab || !activeTab.id) {
              sendResponse({ success: false, error: 'No active tab found' });
              return;
            }

            let result = activeTabScans.get(activeTab.id);
            if (!result && activeTab.url) {
              result = await scanTab(activeTab.id, activeTab.url);
            }
            sendResponse({ success: true, data: result, tab: activeTab });
            break;
          }

          case 'MANUAL_SCAN_TAB': {
            const tabId = message.tabId;
            const url = message.url;
            const result = await scanTab(tabId, url);
            sendResponse({ success: true, data: result });
            break;
          }

          case 'MANUAL_SCAN_URL': {
            const result = await scanArbitraryUrl(message.url);
            sendResponse({ success: true, data: result });
            break;
          }

          case 'PAGE_DOM_ANALYSIS': {
            const tabId = sender.tab ? sender.tab.id : null;
            if (tabId && sender.tab.url) {
              const updatedScan = await scanTab(tabId, sender.tab.url, message.data);
              sendResponse({ success: true, data: updatedScan });
            } else {
              sendResponse({ success: false, error: 'Missing tab context' });
            }
            break;
          }

          case 'GET_SETTINGS': {
            const settings = await StorageManager.getSettings();
            sendResponse({ success: true, data: settings });
            break;
          }

          case 'UPDATE_SETTINGS': {
            const settings = await StorageManager.saveSettings(message.settings);
            // Refresh badge on current tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.id) {
              const currentScan = activeTabScans.get(tab.id);
              updateBadge(tab.id, currentScan, settings.protectionEnabled);
            }
            sendResponse({ success: true, data: settings });
            break;
          }

          case 'GET_HISTORY': {
            const history = await StorageManager.getScanHistory();
            sendResponse({ success: true, data: history });
            break;
          }

          case 'CLEAR_HISTORY': {
            await StorageManager.clearScanHistory();
            sendResponse({ success: true });
            break;
          }

          case 'ADD_ALLOWLIST': {
            await StorageManager.addToAllowlist(message.domain);
            sendResponse({ success: true });
            break;
          }

          case 'REMOVE_ALLOWLIST': {
            await StorageManager.removeFromAllowlist(message.domain);
            sendResponse({ success: true });
            break;
          }

          case 'ADD_BLOCKLIST': {
            await StorageManager.addToBlocklist(message.domain);
            sendResponse({ success: true });
            break;
          }

          case 'REMOVE_BLOCKLIST': {
            await StorageManager.removeFromBlocklist(message.domain);
            sendResponse({ success: true });
            break;
          }

          case 'INITIATE_INVESTIGATION': {
            const settings = await StorageManager.getSettings();
            if (!settings.backendUrl) {
              sendResponse({ success: false, error: 'Backend URL not configured' });
              break;
            }
            try {
              const bUrl = settings.backendUrl.replace(/\/+$/, '');
              const apiKey = settings.backendApiKey || 'sentinelx-client-dev-key';
              const resp = await fetch(`${bUrl}/api/v1/investigations`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-CyberSentry-Key': apiKey,
                  'X-SentinelX-Key': apiKey
                },
                body: JSON.stringify({
                  url: message.url,
                  scanId: message.scanId,
                  clientIdentity: 'browser-extension-client'
                })
              });
              const json = await resp.json();
              sendResponse(json);
            } catch (err) {
              sendResponse({ success: false, error: `Backend connection error: ${err.message}` });
            }
            break;
          }

          case 'CHECK_BACKEND_HEALTH': {
            const settings = await StorageManager.getSettings();
            if (!settings.backendUrl) {
              sendResponse({ success: false, status: 'unconfigured' });
              break;
            }
            try {
              const bUrl = settings.backendUrl.replace(/\/+$/, '');
              const controller = new AbortController();
              const to = setTimeout(() => controller.abort(), 2000);
              const resp = await fetch(`${bUrl}/health`, { signal: controller.signal });
              clearTimeout(to);
              sendResponse({ success: resp.ok, status: resp.ok ? 'online' : 'error' });
            } catch {
              sendResponse({ success: false, status: 'offline' });
            }
            break;
          }

          default:
            sendResponse({ success: false, error: `Unknown message type: ${message.type}` });
        }
      } catch (err) {
        console.error('[SentinelX Worker] Message handler error:', err);
        sendResponse({ success: false, error: err.message });
      }
    })();

    return true; // Keep message channel open for async response
  });
}

