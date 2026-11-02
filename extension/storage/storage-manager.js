/**
 * SentinelX – Storage Manager
 * Handles extension settings, scan history, allowlist, and blocklist using chrome.storage.local.
 * Includes graceful memory fallback for testing environments.
 */

const DEFAULT_SETTINGS = {
  protectionEnabled: true,
  notificationsEnabled: true,
  notificationThreshold: 'high', // 'all' (moderate+) or 'high' (high & critical)
  autoScanEnabled: true,
  downloadMonitoringEnabled: true,
  phishingDetectionEnabled: true,
  allowlist: [
    'google.com',
    'microsoft.com',
    'apple.com',
    'github.com',
    'wikipedia.org',
    'mozilla.org'
  ],
  blocklist: [],
  backendUrl: 'http://127.0.0.1:8000',
  backendApiKey: 'sentinelx-client-dev-key',
  telemetryEnabled: true,
  backendEnrichmentEnabled: true
};

const MAX_HISTORY_ITEMS = 500;

// In-memory fallback storage for environments where chrome.storage is not available (e.g. unit tests)
const memoryStore = {
  sentinelx_settings: { ...DEFAULT_SETTINGS },
  sentinelx_history: [],
  sentinelx_tab_cache: {}
};

function hasChromeStorage() {
  return typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
}

/**
 * Low-level storage getter
 */
async function getStorageItem(key, defaultValue) {
  if (hasChromeStorage()) {
    return new Promise((resolve) => {
      chrome.storage.local.get([key], (result) => {
        if (chrome.runtime && chrome.runtime.lastError) {
          console.warn(`[SentinelX Storage] Error reading ${key}:`, chrome.runtime.lastError);
          resolve(defaultValue);
        } else {
          resolve(result[key] !== undefined ? result[key] : defaultValue);
        }
      });
    });
  }
  return memoryStore[key] !== undefined ? memoryStore[key] : defaultValue;
}

/**
 * Low-level storage setter
 */
async function setStorageItem(key, value) {
  if (hasChromeStorage()) {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: value }, () => {
        if (chrome.runtime && chrome.runtime.lastError) {
          console.warn(`[SentinelX Storage] Error writing ${key}:`, chrome.runtime.lastError);
        }
        resolve();
      });
    });
  }
  memoryStore[key] = value;
}

/**
 * Storage Manager API
 */
export const StorageManager = {
  /**
   * Get user settings, merged with defaults
   */
  async getSettings() {
    const saved = await getStorageItem('sentinelx_settings', {});
    return { ...DEFAULT_SETTINGS, ...saved };
  },

  /**
   * Save entire settings object
   */
  async saveSettings(settings) {
    const current = await this.getSettings();
    const updated = { ...current, ...settings };
    await setStorageItem('sentinelx_settings', updated);
    return updated;
  },

  /**
   * Update a single setting
   */
  async updateSetting(key, value) {
    const settings = await this.getSettings();
    settings[key] = value;
    await setStorageItem('sentinelx_settings', settings);
    return settings;
  },

  /**
   * Reset settings to default
   */
  async resetSettings() {
    await setStorageItem('sentinelx_settings', { ...DEFAULT_SETTINGS });
    return { ...DEFAULT_SETTINGS };
  },

  /**
   * Check if a domain is allowlisted
   */
  async isAllowlisted(domain) {
    if (!domain) return false;
    const clean = domain.toLowerCase().trim();
    const settings = await this.getSettings();
    const list = settings.allowlist || [];
    return list.some(item => clean === item.toLowerCase() || clean.endsWith('.' + item.toLowerCase()));
  },

  /**
   * Check if a domain is blocklisted
   */
  async isBlocklisted(domain) {
    if (!domain) return false;
    const clean = domain.toLowerCase().trim();
    const settings = await this.getSettings();
    const list = settings.blocklist || [];
    return list.some(item => clean === item.toLowerCase() || clean.endsWith('.' + item.toLowerCase()));
  },

  /**
   * Add a domain to allowlist
   */
  async addToAllowlist(domain) {
    if (!domain) return false;
    const clean = domain.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0];
    const settings = await this.getSettings();
    const list = new Set(settings.allowlist || []);
    list.add(clean);
    // Remove from blocklist if present
    const blocklist = (settings.blocklist || []).filter(item => item.toLowerCase() !== clean);
    settings.allowlist = Array.from(list);
    settings.blocklist = blocklist;
    await this.saveSettings(settings);
    return true;
  },

  /**
   * Remove a domain from allowlist
   */
  async removeFromAllowlist(domain) {
    if (!domain) return false;
    const clean = domain.toLowerCase().trim();
    const settings = await this.getSettings();
    settings.allowlist = (settings.allowlist || []).filter(item => item.toLowerCase() !== clean);
    await this.saveSettings(settings);
    return true;
  },

  /**
   * Add a domain to blocklist
   */
  async addToBlocklist(domain) {
    if (!domain) return false;
    const clean = domain.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0];
    const settings = await this.getSettings();
    const list = new Set(settings.blocklist || []);
    list.add(clean);
    // Remove from allowlist if present
    const allowlist = (settings.allowlist || []).filter(item => item.toLowerCase() !== clean);
    settings.blocklist = Array.from(list);
    settings.allowlist = allowlist;
    await this.saveSettings(settings);
    return true;
  },

  /**
   * Remove a domain from blocklist
   */
  async removeFromBlocklist(domain) {
    if (!domain) return false;
    const clean = domain.toLowerCase().trim();
    const settings = await this.getSettings();
    settings.blocklist = (settings.blocklist || []).filter(item => item.toLowerCase() !== clean);
    await this.saveSettings(settings);
    return true;
  },

  /**
   * Retrieve all scan history
   */
  async getScanHistory() {
    return await getStorageItem('sentinelx_history', []);
  },

  /**
   * Add a scan result to history (with pruning)
   */
  async addScanHistory(scanRecord) {
    if (!scanRecord || !scanRecord.domain) return;
    const history = await this.getScanHistory();

    const record = {
      id: scanRecord.eventId || `scan_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      timestamp: scanRecord.timestamp || new Date().toISOString(),
      domain: scanRecord.domain,
      url: scanRecord.url || '',
      riskScore: typeof scanRecord.riskScore === 'number' ? scanRecord.riskScore : (scanRecord.score || 0),
      riskCategory: scanRecord.riskCategory || scanRecord.category || 'Low Risk',
      severity: scanRecord.severity || 'low',
      confidence: scanRecord.confidence || 'Medium',
      indicators: (scanRecord.indicators || []).map(ind => ({
        id: ind.id,
        name: ind.name,
        severity: ind.severity,
        weight: ind.weight,
        scoreContribution: ind.scoreContribution || ind.weight,
        description: ind.description,
        category: ind.category
      })),
      reasons: scanRecord.reasons || [],
      recommendedAction: scanRecord.recommendedAction || 'Normal browsing'
    };

    // Prepend new record
    const updatedHistory = [record, ...history.filter(item => item.id !== record.id)];
    if (updatedHistory.length > MAX_HISTORY_ITEMS) {
      updatedHistory.length = MAX_HISTORY_ITEMS;
    }

    await setStorageItem('sentinelx_history', updatedHistory);
    return record;
  },

  /**
   * Clear all scan history
   */
  async clearScanHistory() {
    await setStorageItem('sentinelx_history', []);
    return true;
  },

  /**
   * Tab-specific active scan cache (in-memory & local)
   */
  async getTabScan(tabId) {
    const cache = await getStorageItem('sentinelx_tab_cache', {});
    return cache[tabId] || null;
  },

  async setTabScan(tabId, scanResult) {
    const cache = await getStorageItem('sentinelx_tab_cache', {});
    cache[tabId] = scanResult;
    await setStorageItem('sentinelx_tab_cache', cache);
  },

  async removeTabScan(tabId) {
    const cache = await getStorageItem('sentinelx_tab_cache', {});
    delete cache[tabId];
    await setStorageItem('sentinelx_tab_cache', cache);
  }
};

