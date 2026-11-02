/**
 * SentinelX – Content Script Page Monitor
 * Safely inspects webpage structural properties (forms, password fields, actions, title)
 * to detect client-side phishing and credential harvesting techniques.
 *
 * PRIVACY GUARANTEE:
 * - NO user keystrokes recorded.
 * - NO passwords collected or read.
 * - NO form input values inspected, saved, or transmitted.
 * - Only structural metadata (attributes, tags, action destinations) analyzed.
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__sentinelx_page_monitor_installed) return;
  window.__sentinelx_page_monitor_installed = true;

  // Basic IP regex for action checking
  const IP_PATTERN = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  let lastSentAnalysis = null;
  let debounceTimeout = null;

  function analyzeDom() {
    try {
      const currentUrl = window.location.href;
      const currentHost = window.location.hostname.toLowerCase();
      const isHttp = window.location.protocol === 'http:';

      // 1. Password input detection
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      const hasPasswordInput = passwordInputs.length > 0;
      const passwordOverHttp = hasPasswordInput && isHttp;

      // 2. Form analysis
      const forms = document.querySelectorAll('form');
      let suspiciousExternalFormAction = false;
      let externalActionHost = null;
      let formActionIsIp = false;

      forms.forEach(form => {
        const action = form.getAttribute('action');
        if (!action) return;

        try {
          // Resolve relative or absolute URL
          const resolvedAction = new URL(action, window.location.href);
          const actionHost = resolvedAction.hostname.toLowerCase();

          // Check if destination is a raw IP
          if (IP_PATTERN.test(actionHost)) {
            formActionIsIp = true;
          }

          // Check if form has password/credential fields and points to an external host
          const hasCredentialsInForm = form.querySelector('input[type="password"], input[name*="pass" i], input[name*="user" i]');
          if (hasCredentialsInForm && actionHost && actionHost !== currentHost) {
            // Check if not just a common subdomain (e.g. login.example.com to auth.example.com)
            const getRoot = (h) => {
              const p = h.split('.');
              return p.length > 2 ? `${p[p.length - 2]}.${p[p.length - 1]}` : h;
            };
            if (getRoot(actionHost) !== getRoot(currentHost)) {
              suspiciousExternalFormAction = true;
              externalActionHost = actionHost;
            }
          }
        } catch {
          // Invalid URL in action attribute
        }
      });

      const analysisPayload = {
        url: currentUrl,
        hostname: currentHost,
        pageTitle: (document.title || '').trim().substring(0, 150),
        hasPasswordInput,
        passwordOverHttp,
        suspiciousExternalFormAction,
        externalActionHost,
        formActionIsIp,
        formCount: forms.length,
        passwordFieldCount: passwordInputs.length
      };

      // Only dispatch if changed
      const serialized = JSON.stringify(analysisPayload);
      if (serialized === lastSentAnalysis) return;
      lastSentAnalysis = serialized;

      if (chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'PAGE_DOM_ANALYSIS',
          data: analysisPayload
        }, () => {
          // Handle response or context invalidation cleanly
          if (chrome.runtime.lastError) {
            // Extension might have reloaded, silence console error
          }
        });
      }
    } catch (err) {
      console.warn('[SentinelX Page Monitor] DOM analysis error:', err);
    }
  }

  // Initial scan on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', analyzeDom);
  } else {
    analyzeDom();
  }

  // MutationObserver for dynamic SPAs
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(analyzeDom, 800);
  });

  observer.observe(document.documentElement || document.body, {
    childList: true,
    subtree: true,
    attributes: false
  });
})();

