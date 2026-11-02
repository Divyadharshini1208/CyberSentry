/**
 * SentinelX – Notification Manager
 * Delivers actionable security alerts via Chrome Notifications API with smart deduplication.
 */

const NOTIFICATION_COOLDOWN_MS = 5 * 60 * 1000; // 5-minute cooldown per domain

export class NotificationManager {
  constructor() {
    // Map domain -> timestamp of last notification
    this.recentAlerts = new Map();
  }

  /**
   * Determine if notification can be shown (deduplication check)
   */
  shouldAlert(key, severity) {
    const lastTime = this.recentAlerts.get(key);
    const now = Date.now();

    // Critical alerts bypass half the cooldown
    const effectiveCooldown = severity === 'critical' ? NOTIFICATION_COOLDOWN_MS / 2 : NOTIFICATION_COOLDOWN_MS;

    if (lastTime && (now - lastTime) < effectiveCooldown) {
      return false;
    }

    this.recentAlerts.set(key, now);
    return true;
  }

  /**
   * Notify for a website risk evaluation
   */
  async notifyWebsiteRisk(scanResult, settings = null) {
    if (!scanResult) return;

    const { domain, riskScore, riskCategory, severity, indicators, reasons } = scanResult;

    // Check user settings
    if (settings) {
      if (!settings.notificationsEnabled) return;
      if (settings.notificationThreshold === 'high' && severity !== 'high' && severity !== 'critical') {
        return;
      }
    } else {
      if (severity !== 'high' && severity !== 'critical') return;
    }

    if (!this.shouldAlert(domain, severity)) {
      return;
    }

    const title = severity === 'critical' 
      ? `🚨 CyberSentry Critical Threat: ${domain}`
      : `⚠️ CyberSentry Warning: ${domain}`;

    const topReason = (reasons && reasons.length > 0) 
      ? reasons[0] 
      : `Risk Score: ${riskScore}/100 (${riskCategory})`;

    const message = `${topReason}\nAction: ${scanResult.recommendedAction || 'Exercise caution'}`;

    this.sendChromeNotification({
      id: `threat_${domain}_${Date.now()}`,
      title,
      message,
      iconUrl: 'icons/icon48.png',
      priority: severity === 'critical' ? 2 : 1
    });
  }

  /**
   * Notify for a suspicious download
   */
  notifyDownloadWarning(downloadInfo) {
    const { filename, riskReason, severity } = downloadInfo;

    const title = severity === 'critical'
      ? `🛑 CyberSentry Blocked Download: ${filename}`
      : `⚠️ CyberSentry Download Warning: ${filename}`;

    const message = `${riskReason}\nFile has been flagged for safety review.`;

    this.sendChromeNotification({
      id: `download_${Date.now()}`,
      title,
      message,
      iconUrl: 'icons/icon48.png',
      priority: 2
    });
  }

  /**
   * Send notification via Chrome API
   */
  sendChromeNotification(options) {
    if (typeof chrome !== 'undefined' && chrome.notifications && chrome.notifications.create) {
      chrome.notifications.create(options.id, {
        type: 'basic',
        iconUrl: options.iconUrl || 'icons/icon48.png',
        title: options.title,
        message: options.message,
        priority: options.priority || 1
      }, (notificationId) => {
        if (chrome.runtime && chrome.runtime.lastError) {
          console.warn('[SentinelX Notifications] Error displaying notification:', chrome.runtime.lastError);
        }
      });
    } else {
      console.log('[SentinelX Notification Mock]', options.title, '-', options.message);
    }
  }
}

export const notificationManager = new NotificationManager();

