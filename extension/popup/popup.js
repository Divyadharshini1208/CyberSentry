/**
 * SentinelX – Popup Controller
 * Connects the popup UI to real-time tab analysis, settings, and manual scanning.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
  const protectionBadge = document.getElementById('protection-status-badge');
  const cloudStatusBadge = document.getElementById('cloud-status-badge');
  const btnOpenHistory = document.getElementById('btn-open-history');
  const btnOpenSettings = document.getElementById('btn-open-settings');

  const tabBtnActive = document.getElementById('tab-btn-active');
  const tabBtnManual = document.getElementById('tab-btn-manual');
  const activeScanView = document.getElementById('active-scan-view');
  const manualScanView = document.getElementById('manual-scan-view');

  const domainProtocolBadge = document.getElementById('domain-protocol-badge');
  const currentDomainText = document.getElementById('current-domain-text');
  const btnQuickAllow = document.getElementById('btn-quick-allow');
  const btnQuickBlock = document.getElementById('btn-quick-block');

  const gaugeFill = document.getElementById('gauge-fill');
  const riskScoreValue = document.getElementById('risk-score-value');
  const riskCategoryBadge = document.getElementById('risk-category-badge');
  const riskSummaryText = document.getElementById('risk-summary-text');
  const recommendationText = document.getElementById('recommendation-text');

  const indicatorsCountBadge = document.getElementById('indicators-count-badge');
  const indicatorsList = document.getElementById('indicators-list');

  const btnScanNow = document.getElementById('btn-scan-now');
  const btnViewDetails = document.getElementById('btn-view-details');

  // Modal Elements
  const detailsModal = document.getElementById('details-modal');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const modalFullUrl = document.getElementById('modal-full-url');
  const btnCopyUrl = document.getElementById('btn-copy-url');
  const modalRootDomain = document.getElementById('modal-root-domain');
  const modalProtocol = document.getElementById('modal-protocol');
  const modalSubdomains = document.getElementById('modal-subdomains');
  const modalConfidence = document.getElementById('modal-confidence');

  const breakdownProtocolVal = document.getElementById('breakdown-protocol-val');
  const barProtocol = document.getElementById('bar-protocol');
  const breakdownUrlVal = document.getElementById('breakdown-url-val');
  const barUrl = document.getElementById('bar-url');
  const breakdownDomainVal = document.getElementById('breakdown-domain-val');
  const barDomain = document.getElementById('bar-domain');
  const breakdownPhishingVal = document.getElementById('breakdown-phishing-val');
  const barPhishing = document.getElementById('bar-phishing');
  const breakdownRedirectVal = document.getElementById('breakdown-redirect-val');
  const barRedirect = document.getElementById('bar-redirect');

  const modalRedirectHops = document.getElementById('modal-redirect-hops');
  const modalIntelSource = document.getElementById('modal-intel-source');
  const modalCloudStatus = document.getElementById('modal-cloud-status');
  const modalMlStatus = document.getElementById('modal-ml-status');
  const modalTimestamp = document.getElementById('modal-timestamp');
  const btnDeepInvestigate = document.getElementById('btn-deep-investigate');
  const investigationResultCard = document.getElementById('investigation-result-card');
  const investigationSummaryText = document.getElementById('investigation-summary-text');

  // Manual Scan Elements
  const manualUrlInput = document.getElementById('manual-url-input');
  const btnRunManualScan = document.getElementById('btn-run-manual-scan');
  const manualScanResult = document.getElementById('manual-scan-result');

  const toast = document.getElementById('popup-toast');

  let currentTabInfo = null;
  let currentScanData = null;
  let currentSettings = null;

  // Show Toast Message
  function showToast(message, durationMs = 2000) {
    toast.textContent = message;
    toast.classList.remove('hidden');
    setTimeout(() => {
      toast.classList.add('hidden');
    }, durationMs);
  }

  // Update SVG Risk Gauge
  function updateGauge(score, color) {
    const circumference = 2 * Math.PI * 42; // ~263.89
    const clamped = Math.max(0, Math.min(100, score || 0));
    const offset = circumference - (clamped / 100) * circumference;

    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.stroke = color || '#10b981';
    riskScoreValue.textContent = clamped;
  }

  // Render Detected Indicators List
  function renderIndicators(indicators) {
    indicatorsList.innerHTML = '';
    indicatorsCountBadge.textContent = indicators.length;

    if (!indicators || indicators.length === 0) {
      const emptyDiv = document.createElement('div');
      emptyDiv.className = 'empty-indicators';
      emptyDiv.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <span>No malicious patterns or anomalies detected.</span>
      `;
      indicatorsList.appendChild(emptyDiv);
      return;
    }

    indicators.forEach(ind => {
      const row = document.createElement('div');
      row.className = `indicator-row severity-${ind.severity || 'moderate'}`;

      const header = document.createElement('div');
      header.className = 'indicator-header';

      const name = document.createElement('span');
      name.className = 'indicator-name';
      name.textContent = ind.name;

      const weight = document.createElement('span');
      weight.className = 'indicator-weight';
      weight.textContent = ind.scoreContribution ? `+${ind.scoreContribution} pts` : `weight: ${ind.weight || 0}`;

      header.appendChild(name);
      header.appendChild(weight);

      const desc = document.createElement('span');
      desc.className = 'indicator-desc';
      desc.textContent = ind.description;

      row.appendChild(header);
      row.appendChild(desc);
      indicatorsList.appendChild(row);
    });
  }

  // Populate Active Tab View
  function renderActiveScan(scanResult, tab) {
    currentScanData = scanResult;
    currentTabInfo = tab;

    if (!scanResult) {
      currentDomainText.textContent = 'Unable to scan active tab';
      riskSummaryText.textContent = 'Please navigate to a webpage and click Scan Now.';
      return;
    }

    // Protocol badge
    let protocolLabel = 'HTTPS';
    let protocolClass = 'https';
    if (scanResult.unsupported) {
      protocolLabel = 'SYS';
      protocolClass = 'internal';
    } else if (scanResult.url && scanResult.url.startsWith('http://')) {
      protocolLabel = 'HTTP';
      protocolClass = 'http';
    }
    domainProtocolBadge.textContent = protocolLabel;
    domainProtocolBadge.className = `protocol-badge ${protocolClass}`;

    // Domain
    currentDomainText.textContent = scanResult.domain || 'Unknown';
    currentDomainText.title = scanResult.url || scanResult.domain;

    // Risk Meter & Category
    const score = scanResult.riskScore || 0;
    const tierColor = scanResult.color || (score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#f59e0b' : '#10b981');
    updateGauge(score, tierColor);

    const categoryName = scanResult.riskCategory || (score >= 75 ? 'Critical Risk' : score >= 50 ? 'High Risk' : score >= 25 ? 'Moderate Risk' : 'Low Risk');
    riskCategoryBadge.textContent = categoryName;

    let catClass = 'low';
    if (score >= 75) catClass = 'critical';
    else if (score >= 50) catClass = 'high';
    else if (score >= 25) catClass = 'moderate';

    riskCategoryBadge.className = `category-badge ${catClass}`;

    // Summary Text
    if (scanResult.isAllowlisted) {
      riskSummaryText.textContent = 'Domain is explicitly trusted via user allowlist.';
    } else if (scanResult.isBlocklisted) {
      riskSummaryText.textContent = 'Domain is restricted by user security blocklist.';
    } else if (scanResult.paused) {
      riskSummaryText.textContent = 'Protection is paused. Threat scanning is inactive.';
    } else if (scanResult.reasons && scanResult.reasons.length > 0) {
      riskSummaryText.textContent = scanResult.reasons[0];
    } else {
      riskSummaryText.textContent = 'Normal web traffic. Security standards verified.';
    }

    // Recommendation
    recommendationText.textContent = scanResult.recommendedAction || 'Safe to browse.';

    // Indicators
    renderIndicators(scanResult.indicators || []);
  }

  // Populate Detailed Modal
  function populateDetailsModal(scan) {
    if (!scan) return;

    modalFullUrl.textContent = scan.url || 'N/A';
    modalRootDomain.textContent = scan.domain || '-';
    modalProtocol.textContent = (scan.url && scan.url.startsWith('https://')) ? 'HTTPS (Encrypted TLS)' : 'HTTP (Unencrypted)';
    
    // Subdomains
    const subCount = scan.breakdown ? (scan.metrics && scan.metrics.subdomainCount !== undefined ? scan.metrics.subdomainCount : 0) : 0;
    modalSubdomains.textContent = `${subCount} subdomain(s)`;
    modalConfidence.textContent = scan.confidence || 'Medium';

    // Breakdown bars
    const bd = scan.breakdown || {};
    const maxVal = Math.max(1, (scan.riskScore || 0));

    const setBar = (valSpan, barDiv, val) => {
      const safeVal = val || 0;
      valSpan.textContent = `+${safeVal}`;
      const pct = Math.min(100, Math.round((safeVal / maxVal) * 100));
      barDiv.style.width = `${pct}%`;
    };

    setBar(breakdownProtocolVal, barProtocol, bd.protocol);
    setBar(breakdownUrlVal, barUrl, bd.url_structure);
    setBar(breakdownDomainVal, barDomain, bd.domain_intelligence);
    setBar(breakdownPhishingVal, barPhishing, bd.phishing);
    setBar(breakdownRedirectVal, barRedirect, bd.redirect);

    // Redirect Hops
    modalRedirectHops.innerHTML = '';
    const hops = (scan.redirectDetails && scan.redirectDetails.hops) ? scan.redirectDetails.hops : [];

    if (hops.length <= 1) {
      modalRedirectHops.innerHTML = '<div class="no-hops-text">Direct navigation (No intermediate redirects detected)</div>';
    } else {
      hops.forEach((hop, idx) => {
        const item = document.createElement('div');
        item.className = 'hop-item';
        item.innerHTML = `
          <span class="hop-badge">Hop ${idx + 1}</span>
          <span class="url-truncate">${hop.url}</span>
        `;
        modalRedirectHops.appendChild(item);
      });
    }

    modalIntelSource.textContent = scan.threatIntelligenceStatus || 'Local Heuristic Engine V1';
    modalTimestamp.textContent = scan.timestamp ? new Date(scan.timestamp).toLocaleString() : new Date().toLocaleString();

    // Backend cloud intelligence status
    if (scan.backendAnalysis && scan.backendAnalysis.status === 'online') {
      modalCloudStatus.textContent = 'Online (Enriched via Cloud Intel)';
      modalCloudStatus.style.color = '#00e5ff';
      if (scan.backendAnalysis.mlPrediction && scan.backendAnalysis.mlPrediction.prediction) {
        const ml = scan.backendAnalysis.mlPrediction;
        modalMlStatus.textContent = `${ml.prediction.toUpperCase()} (${Math.round(ml.probability * 100)}% risk)`;
      } else {
        modalMlStatus.textContent = 'Evaluated';
      }
    } else if (scan.backendAnalysis && scan.backendAnalysis.status === 'offline') {
      modalCloudStatus.textContent = 'Offline (Autonomous Local Mode)';
      modalCloudStatus.style.color = '#94a3b8';
      modalMlStatus.textContent = 'Offline';
    } else {
      modalCloudStatus.textContent = 'Local Autonomous Mode';
      modalCloudStatus.style.color = '#94a3b8';
      modalMlStatus.textContent = 'Standby';
    }

    if (investigationResultCard) {
      investigationResultCard.classList.add('hidden');
    }
  }

  // Load Initial Data
  async function loadData() {
    try {
      // 1. Fetch settings
      const settingsResp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
      if (settingsResp && settingsResp.data) {
        currentSettings = settingsResp.data;
        if (!currentSettings.protectionEnabled) {
          protectionBadge.textContent = 'Paused';
          protectionBadge.className = 'status-badge paused';
        } else {
          protectionBadge.textContent = 'Active';
          protectionBadge.className = 'status-badge active';
        }
      }

      // Check backend health
      try {
        const healthResp = await chrome.runtime.sendMessage({ type: 'CHECK_BACKEND_HEALTH' });
        if (healthResp && healthResp.status === 'online') {
          cloudStatusBadge.textContent = 'Cloud: Online';
          cloudStatusBadge.className = 'cloud-badge online';
        } else {
          cloudStatusBadge.textContent = 'Local Mode';
          cloudStatusBadge.className = 'cloud-badge offline';
        }
      } catch {
        cloudStatusBadge.textContent = 'Local Mode';
        cloudStatusBadge.className = 'cloud-badge offline';
      }

      // 2. Fetch active tab scan
      const scanResp = await chrome.runtime.sendMessage({ type: 'GET_ACTIVE_TAB_SCAN' });
      if (scanResp && scanResp.success) {
        renderActiveScan(scanResp.data, scanResp.tab);
      }
    } catch (err) {
      console.warn('[SentinelX Popup] Initialization warning:', err);
    }
  }

  // Tab switching
  tabBtnActive.addEventListener('click', () => {
    tabBtnActive.classList.add('active');
    tabBtnManual.classList.remove('active');
    activeScanView.classList.add('active');
    manualScanView.classList.remove('active');
  });

  tabBtnManual.addEventListener('click', () => {
    tabBtnManual.classList.add('active');
    tabBtnActive.classList.remove('active');
    manualScanView.classList.add('active');
    activeScanView.classList.remove('active');
  });

  // Toggle Protection on badge click
  protectionBadge.addEventListener('click', async () => {
    if (!currentSettings) return;
    const newState = !currentSettings.protectionEnabled;
    currentSettings.protectionEnabled = newState;

    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: currentSettings
    });

    if (newState) {
      protectionBadge.textContent = 'Active';
      protectionBadge.className = 'status-badge active';
      showToast('Protection Activated');
    } else {
      protectionBadge.textContent = 'Paused';
      protectionBadge.className = 'status-badge paused';
      showToast('Protection Paused');
    }

    // Rescan active tab
    if (currentTabInfo && currentTabInfo.id) {
      const res = await chrome.runtime.sendMessage({
        type: 'MANUAL_SCAN_TAB',
        tabId: currentTabInfo.id,
        url: currentTabInfo.url
      });
      if (res && res.data) renderActiveScan(res.data, currentTabInfo);
    }
  });

  // Scan Now button
  btnScanNow.addEventListener('click', async () => {
    if (!currentTabInfo || !currentTabInfo.id) return;

    btnScanNow.classList.add('scanning');
    btnScanNow.querySelector('span').textContent = 'Scanning...';

    try {
      const res = await chrome.runtime.sendMessage({
        type: 'MANUAL_SCAN_TAB',
        tabId: currentTabInfo.id,
        url: currentTabInfo.url
      });
      if (res && res.data) {
        renderActiveScan(res.data, currentTabInfo);
        showToast('Scan Completed');
      }
    } finally {
      btnScanNow.classList.remove('scanning');
      btnScanNow.querySelector('span').textContent = 'Scan Now';
    }
  });

  // Modal handlers
  btnViewDetails.addEventListener('click', () => {
    populateDetailsModal(currentScanData);
    detailsModal.classList.remove('hidden');
  });

  btnCloseModal.addEventListener('click', () => {
    detailsModal.classList.add('hidden');
  });

  detailsModal.addEventListener('click', (e) => {
    if (e.target === detailsModal) {
      detailsModal.classList.add('hidden');
    }
  });

  btnCopyUrl.addEventListener('click', async () => {
    if (currentScanData && currentScanData.url) {
      await navigator.clipboard.writeText(currentScanData.url);
      showToast('URL Copied to Clipboard');
    }
  });

  // Deep Multi-Agent Investigation Trigger
  if (btnDeepInvestigate) {
    btnDeepInvestigate.addEventListener('click', async () => {
      if (!currentScanData || !currentScanData.url) return;

      btnDeepInvestigate.disabled = true;
      btnDeepInvestigate.querySelector('span').textContent = 'Orchestrating 8 Agents...';

      try {
        const resp = await chrome.runtime.sendMessage({
          type: 'INITIATE_INVESTIGATION',
          url: currentScanData.url,
          scanId: currentScanData.eventId
        });

        if (resp && resp.success && resp.data) {
          const inv = resp.data;
          investigationResultCard.classList.remove('hidden');
          investigationSummaryText.textContent = `${inv.orchestratorSummary}\nRecommended Action: ${inv.recommendedAction}`;
          showToast('Investigation Completed');
        } else {
          showToast(resp.error || 'Investigation could not be completed');
        }
      } catch (err) {
        showToast('Backend unavailable for deep investigation');
      } finally {
        btnDeepInvestigate.disabled = false;
        btnDeepInvestigate.querySelector('span').textContent = 'Run Multi-Agent Investigation';
      }
    });
  }

  // Quick Allowlist button
  btnQuickAllow.addEventListener('click', async () => {
    if (!currentScanData || !currentScanData.domain) return;
    await chrome.runtime.sendMessage({
      type: 'ADD_ALLOWLIST',
      domain: currentScanData.domain
    });
    showToast(`Trusted ${currentScanData.domain}`);
    // Rescan tab to reflect allowlist
    if (currentTabInfo) {
      const res = await chrome.runtime.sendMessage({
        type: 'MANUAL_SCAN_TAB',
        tabId: currentTabInfo.id,
        url: currentTabInfo.url
      });
      if (res && res.data) renderActiveScan(res.data, currentTabInfo);
    }
  });

  // Quick Blocklist button
  btnQuickBlock.addEventListener('click', async () => {
    if (!currentScanData || !currentScanData.domain) return;
    await chrome.runtime.sendMessage({
      type: 'ADD_BLOCKLIST',
      domain: currentScanData.domain
    });
    showToast(`Blocked ${currentScanData.domain}`);
    // Rescan tab to reflect blocklist
    if (currentTabInfo) {
      const res = await chrome.runtime.sendMessage({
        type: 'MANUAL_SCAN_TAB',
        tabId: currentTabInfo.id,
        url: currentTabInfo.url
      });
      if (res && res.data) renderActiveScan(res.data, currentTabInfo);
    }
  });

  // Manual URL Scan execution
  btnRunManualScan.addEventListener('click', async () => {
    const inputUrl = manualUrlInput.value.trim();
    if (!inputUrl) {
      showToast('Please enter a valid URL');
      return;
    }

    btnRunManualScan.textContent = '...';
    try {
      const res = await chrome.runtime.sendMessage({
        type: 'MANUAL_SCAN_URL',
        url: inputUrl
      });

      if (res && res.data) {
        const scan = res.data;
        manualScanResult.classList.remove('hidden');

        let catClass = 'low';
        if (scan.riskScore >= 75) catClass = 'critical';
        else if (scan.riskScore >= 50) catClass = 'high';
        else if (scan.riskScore >= 25) catClass = 'moderate';

        manualScanResult.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <span class="category-badge ${catClass}">${scan.riskCategory} (${scan.riskScore}/100)</span>
            <span style="font-size:11px; color:#94a3b8;">${scan.confidence} Confidence</span>
          </div>
          <div style="font-weight:600; color:#fff; font-size:13px; margin-bottom:4px;">${scan.domain}</div>
          <div style="font-size:12px; color:#94a3b8; margin-bottom:8px;">${scan.recommendedAction}</div>
          <div style="font-size:11px; color:#64748b;">${scan.reasons.length} detection indicator(s) evaluated.</div>
        `;
      }
    } catch {
      showToast('Error scanning URL');
    } finally {
      btnRunManualScan.textContent = 'Scan';
    }
  });

  // History shortcut
  btnOpenHistory.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('history/history.html') });
  });

  // Settings shortcut
  btnOpenSettings.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('settings/settings.html') });
  });

  // Start initialization
  loadData();
});

