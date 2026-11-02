/**
 * SentinelX – Settings Controller
 * Handles user policies, protection toggles, allowlist, and blocklist management.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Elements
  const toggleProtection = document.getElementById('toggle-protection');
  const togglePhishing = document.getElementById('toggle-phishing');
  const toggleAutoscan = document.getElementById('toggle-autoscan');
  const toggleDownloads = document.getElementById('toggle-downloads');
  const toggleNotifications = document.getElementById('toggle-notifications');
  const selectThreshold = document.getElementById('select-notify-threshold');

  const toggleEnrichment = document.getElementById('toggle-enrichment');
  const toggleTelemetry = document.getElementById('toggle-telemetry');
  const inputBackendUrl = document.getElementById('input-backend-url');
  const inputBackendKey = document.getElementById('input-backend-key');

  const allowlistCount = document.getElementById('allowlist-count-badge');
  const inputNewAllow = document.getElementById('input-new-allow');
  const btnAddAllow = document.getElementById('btn-add-allow');
  const allowlistContainer = document.getElementById('allowlist-container');

  const blocklistCount = document.getElementById('blocklist-count-badge');
  const inputNewBlock = document.getElementById('input-new-block');
  const btnAddBlock = document.getElementById('btn-add-block');
  const blocklistContainer = document.getElementById('blocklist-container');

  const btnClearHistory = document.getElementById('btn-clear-history-settings');
  const btnResetDefaults = document.getElementById('btn-reset-defaults');

  const modal = document.getElementById('settings-confirm-modal');
  const modalTitle = document.getElementById('confirm-modal-title');
  const modalMsg = document.getElementById('confirm-modal-msg');
  const btnModalCancel = document.getElementById('btn-modal-cancel');
  const btnModalConfirm = document.getElementById('btn-modal-confirm');

  const toast = document.getElementById('settings-toast');

  let currentSettings = null;
  let pendingModalAction = null;

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.remove('hidden');
    setTimeout(() => {
      toast.classList.add('hidden');
    }, 2500);
  }

  function cleanDomainInput(raw) {
    if (!raw) return '';
    return raw
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//i, '')
      .replace(/^www\./i, '')
      .split('/')[0]
      .split('?')[0]
      .split('#')[0];
  }

  function renderAllowlist() {
    const list = currentSettings.allowlist || [];
    allowlistCount.textContent = `${list.length} domain${list.length === 1 ? '' : 's'}`;
    allowlistContainer.innerHTML = '';

    if (list.length === 0) {
      allowlistContainer.innerHTML = '<span class="empty-pill-msg">No custom allowlisted domains.</span>';
      return;
    }

    list.forEach(domain => {
      const pill = document.createElement('div');
      pill.className = 'domain-pill';

      const label = document.createElement('span');
      label.textContent = domain;

      const btnRemove = document.createElement('button');
      btnRemove.className = 'domain-pill-remove';
      btnRemove.innerHTML = '&times;';
      btnRemove.title = 'Remove domain';
      btnRemove.addEventListener('click', async () => {
        await chrome.runtime.sendMessage({ type: 'REMOVE_ALLOWLIST', domain });
        currentSettings.allowlist = currentSettings.allowlist.filter(d => d !== domain);
        renderAllowlist();
        showToast(`Removed ${domain} from allowlist`);
      });

      pill.appendChild(label);
      pill.appendChild(btnRemove);
      allowlistContainer.appendChild(pill);
    });
  }

  function renderBlocklist() {
    const list = currentSettings.blocklist || [];
    blocklistCount.textContent = `${list.length} domain${list.length === 1 ? '' : 's'}`;
    blocklistContainer.innerHTML = '';

    if (list.length === 0) {
      blocklistContainer.innerHTML = '<span class="empty-pill-msg">No custom blocked domains.</span>';
      return;
    }

    list.forEach(domain => {
      const pill = document.createElement('div');
      pill.className = 'domain-pill';

      const label = document.createElement('span');
      label.textContent = domain;

      const btnRemove = document.createElement('button');
      btnRemove.className = 'domain-pill-remove';
      btnRemove.innerHTML = '&times;';
      btnRemove.title = 'Remove domain';
      btnRemove.addEventListener('click', async () => {
        await chrome.runtime.sendMessage({ type: 'REMOVE_BLOCKLIST', domain });
        currentSettings.blocklist = currentSettings.blocklist.filter(d => d !== domain);
        renderBlocklist();
        showToast(`Removed ${domain} from blocklist`);
      });

      pill.appendChild(label);
      pill.appendChild(btnRemove);
      blocklistContainer.appendChild(pill);
    });
  }

  async function syncSettingsToServer() {
    if (!currentSettings) return;
    const resp = await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: currentSettings
    });
    if (resp && resp.data) {
      currentSettings = resp.data;
      showToast('Settings Saved');
    }
  }

  // Populate UI inputs from settings object
  function syncUIFromSettings() {
    toggleProtection.checked = !!currentSettings.protectionEnabled;
    togglePhishing.checked = !!currentSettings.phishingDetectionEnabled;
    toggleAutoscan.checked = !!currentSettings.autoScanEnabled;
    toggleDownloads.checked = !!currentSettings.downloadMonitoringEnabled;
    toggleNotifications.checked = !!currentSettings.notificationsEnabled;
    selectThreshold.value = currentSettings.notificationThreshold || 'high';

    if (toggleEnrichment) toggleEnrichment.checked = currentSettings.backendEnrichmentEnabled !== false;
    if (toggleTelemetry) toggleTelemetry.checked = currentSettings.telemetryEnabled !== false;
    if (inputBackendUrl) inputBackendUrl.value = currentSettings.backendUrl || 'http://127.0.0.1:8000';
    if (inputBackendKey) inputBackendKey.value = currentSettings.backendApiKey || '';

    renderAllowlist();
    renderBlocklist();
  }

  // Event Listeners for Toggles
  toggleProtection.addEventListener('change', () => {
    currentSettings.protectionEnabled = toggleProtection.checked;
    syncSettingsToServer();
  });

  togglePhishing.addEventListener('change', () => {
    currentSettings.phishingDetectionEnabled = togglePhishing.checked;
    syncSettingsToServer();
  });

  toggleAutoscan.addEventListener('change', () => {
    currentSettings.autoScanEnabled = toggleAutoscan.checked;
    syncSettingsToServer();
  });

  toggleDownloads.addEventListener('change', () => {
    currentSettings.downloadMonitoringEnabled = toggleDownloads.checked;
    syncSettingsToServer();
  });

  toggleNotifications.addEventListener('change', () => {
    currentSettings.notificationsEnabled = toggleNotifications.checked;
    syncSettingsToServer();
  });

  selectThreshold.addEventListener('change', () => {
    currentSettings.notificationThreshold = selectThreshold.value;
    syncSettingsToServer();
  });

  if (toggleEnrichment) {
    toggleEnrichment.addEventListener('change', () => {
      currentSettings.backendEnrichmentEnabled = toggleEnrichment.checked;
      syncSettingsToServer();
    });
  }

  if (toggleTelemetry) {
    toggleTelemetry.addEventListener('change', () => {
      currentSettings.telemetryEnabled = toggleTelemetry.checked;
      syncSettingsToServer();
    });
  }

  if (inputBackendUrl) {
    inputBackendUrl.addEventListener('change', () => {
      currentSettings.backendUrl = inputBackendUrl.value.trim().replace(/\/+$/, '');
      syncSettingsToServer();
    });
  }

  if (inputBackendKey) {
    inputBackendKey.addEventListener('change', () => {
      currentSettings.backendApiKey = inputBackendKey.value.trim();
      syncSettingsToServer();
    });
  }

  // Add to Allowlist
  btnAddAllow.addEventListener('click', async () => {
    const raw = inputNewAllow.value;
    const cleaned = cleanDomainInput(raw);

    if (!cleaned || !cleaned.includes('.')) {
      showToast('Please enter a valid domain (e.g. site.com)');
      return;
    }

    await chrome.runtime.sendMessage({ type: 'ADD_ALLOWLIST', domain: cleaned });
    const set = new Set(currentSettings.allowlist || []);
    set.add(cleaned);
    currentSettings.allowlist = Array.from(set);
    currentSettings.blocklist = (currentSettings.blocklist || []).filter(d => d !== cleaned);

    inputNewAllow.value = '';
    renderAllowlist();
    renderBlocklist();
    showToast(`Added ${cleaned} to allowlist`);
  });

  // Add to Blocklist
  btnAddBlock.addEventListener('click', async () => {
    const raw = inputNewBlock.value;
    const cleaned = cleanDomainInput(raw);

    if (!cleaned || !cleaned.includes('.')) {
      showToast('Please enter a valid domain (e.g. evil-site.com)');
      return;
    }

    await chrome.runtime.sendMessage({ type: 'ADD_BLOCKLIST', domain: cleaned });
    const set = new Set(currentSettings.blocklist || []);
    set.add(cleaned);
    currentSettings.blocklist = Array.from(set);
    currentSettings.allowlist = (currentSettings.allowlist || []).filter(d => d !== cleaned);

    inputNewBlock.value = '';
    renderBlocklist();
    renderAllowlist();
    showToast(`Added ${cleaned} to blocklist`);
  });

  // Clear History Modal
  btnClearHistory.addEventListener('click', () => {
    modalTitle.textContent = 'Clear Scan History';
    modalMsg.textContent = 'Are you sure you want to delete all stored security scan history logs?';
    pendingModalAction = async () => {
      await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
      showToast('Scan History Cleared');
    };
    modal.classList.remove('hidden');
  });

  // Reset to Factory Defaults Modal
  btnResetDefaults.addEventListener('click', () => {
    modalTitle.textContent = 'Reset to Factory Defaults';
    modalMsg.textContent = 'This will reset all protection settings, allowlist, and blocklist back to default.';
    pendingModalAction = async () => {
      const defaultSettings = {
        protectionEnabled: true,
        notificationsEnabled: true,
        notificationThreshold: 'high',
        autoScanEnabled: true,
        downloadMonitoringEnabled: true,
        phishingDetectionEnabled: true,
        allowlist: ['google.com', 'microsoft.com', 'apple.com', 'github.com', 'wikipedia.org', 'mozilla.org'],
        blocklist: []
      };
      await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: defaultSettings });
      currentSettings = defaultSettings;
      syncUIFromSettings();
      showToast('Settings Reset to Defaults');
    };
    modal.classList.remove('hidden');
  });

  btnModalCancel.addEventListener('click', () => {
    modal.classList.add('hidden');
    pendingModalAction = null;
  });

  btnModalConfirm.addEventListener('click', async () => {
    if (pendingModalAction) {
      await pendingModalAction();
    }
    modal.classList.add('hidden');
    pendingModalAction = null;
  });

  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.classList.add('hidden');
      pendingModalAction = null;
    }
  });

  // Initial load
  async function loadSettings() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
      if (resp && resp.data) {
        currentSettings = resp.data;
        syncUIFromSettings();
      }
    } catch (err) {
      console.warn('[SentinelX Settings] Load error:', err);
    }
  }

  loadSettings();
});

