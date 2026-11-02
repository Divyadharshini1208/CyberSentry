/**
 * SentinelX – Scan History Controller
 * Search, filter, inspect, and export scan telemetry.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const statTotal = document.getElementById('stat-total-scans');
  const statThreats = document.getElementById('stat-threat-scans');
  const statSafe = document.getElementById('stat-safe-scans');

  const inputSearch = document.getElementById('input-search');
  const selectFilter = document.getElementById('select-category-filter');
  const selectSort = document.getElementById('select-sort-order');

  const historyTbody = document.getElementById('history-tbody');
  const emptyState = document.getElementById('empty-state');

  const btnExportCsv = document.getElementById('btn-export-csv');
  const btnClearHistory = document.getElementById('btn-clear-history');

  const confirmModal = document.getElementById('confirm-modal');
  const btnCancelClear = document.getElementById('btn-cancel-clear');
  const btnConfirmClear = document.getElementById('btn-confirm-clear');

  const inspectModal = document.getElementById('inspect-modal');
  const inspectDomainTitle = document.getElementById('inspect-domain-title');
  const inspectModalBody = document.getElementById('inspect-modal-body');
  const btnCloseInspect = document.getElementById('btn-close-inspect');

  const toast = document.getElementById('history-toast');

  let allHistory = [];

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.remove('hidden');
    setTimeout(() => {
      toast.classList.add('hidden');
    }, 2500);
  }

  function getSeverityClass(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'moderate';
    return 'low';
  }

  function updateStats(items) {
    statTotal.textContent = items.length;
    const threats = items.filter(i => (i.riskScore || 0) >= 50).length;
    const safe = items.filter(i => (i.riskScore || 0) <= 24).length;
    statThreats.textContent = threats;
    statSafe.textContent = safe;
  }

  function renderTable() {
    const query = inputSearch.value.trim().toLowerCase();
    const filterCat = selectFilter.value;
    const sortOrder = selectSort.value;

    let filtered = allHistory.filter(item => {
      // Category filter
      if (filterCat !== 'ALL') {
        const cat = item.riskCategory || '';
        if (cat.toLowerCase() !== filterCat.toLowerCase()) return false;
      }

      // Search query
      if (query) {
        const d = (item.domain || '').toLowerCase();
        const u = (item.url || '').toLowerCase();
        const reasons = (item.reasons || []).join(' ').toLowerCase();
        const inds = (item.indicators || []).map(i => i.name).join(' ').toLowerCase();
        if (!d.includes(query) && !u.includes(query) && !reasons.includes(query) && !inds.includes(query)) {
          return false;
        }
      }

      return true;
    });

    // Sorting
    filtered.sort((a, b) => {
      if (sortOrder === 'date-asc') {
        return new Date(a.timestamp) - new Date(b.timestamp);
      } else if (sortOrder === 'score-desc') {
        return (b.riskScore || 0) - (a.riskScore || 0);
      } else {
        // default: date-desc
        return new Date(b.timestamp) - new Date(a.timestamp);
      }
    });

    historyTbody.innerHTML = '';

    if (filtered.length === 0) {
      emptyState.classList.remove('hidden');
      return;
    }

    emptyState.classList.add('hidden');

    filtered.forEach(record => {
      const tr = document.createElement('tr');
      const score = record.riskScore || 0;
      const sevClass = getSeverityClass(score);

      // 1. Timestamp
      const tdTime = document.createElement('td');
      tdTime.className = 'timestamp-cell';
      const d = new Date(record.timestamp);
      tdTime.textContent = isNaN(d) ? record.timestamp : `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;

      // 2. Domain & URL
      const tdDomain = document.createElement('td');
      tdDomain.className = 'domain-cell';
      const dName = document.createElement('span');
      dName.className = 'domain-name';
      dName.textContent = record.domain || 'Unknown';
      const urlSub = document.createElement('span');
      urlSub.className = 'url-subtext';
      urlSub.textContent = record.url || '';
      urlSub.title = record.url || '';
      tdDomain.appendChild(dName);
      tdDomain.appendChild(urlSub);

      // 3. Risk Score
      const tdScore = document.createElement('td');
      const scoreBadge = document.createElement('span');
      scoreBadge.className = `score-badge score-${sevClass}`;
      scoreBadge.textContent = `${score}/100`;
      tdScore.appendChild(scoreBadge);

      // 4. Category
      const tdCat = document.createElement('td');
      const catPill = document.createElement('span');
      catPill.className = `category-pill pill-${sevClass}`;
      catPill.textContent = record.riskCategory || 'Low Risk';
      tdCat.appendChild(catPill);

      // 5. Indicators
      const tdInds = document.createElement('td');
      tdInds.className = 'indicators-cell';
      const inds = record.indicators || [];
      if (inds.length === 0) {
        const safeChip = document.createElement('span');
        safeChip.className = 'indicator-chip';
        safeChip.textContent = 'None (Safe)';
        tdInds.appendChild(safeChip);
      } else {
        inds.slice(0, 3).forEach(ind => {
          const chip = document.createElement('span');
          chip.className = 'indicator-chip';
          chip.textContent = ind.name;
          tdInds.appendChild(chip);
        });
        if (inds.length > 3) {
          const moreChip = document.createElement('span');
          moreChip.className = 'indicator-chip';
          moreChip.textContent = `+${inds.length - 3} more`;
          tdInds.appendChild(moreChip);
        }
      }

      // 6. Action
      const tdAction = document.createElement('td');
      const btnInspect = document.createElement('button');
      btnInspect.className = 'btn-inspect';
      btnInspect.textContent = 'Inspect';
      btnInspect.addEventListener('click', () => openInspectModal(record));
      tdAction.appendChild(btnInspect);

      tr.appendChild(tdTime);
      tr.appendChild(tdDomain);
      tr.appendChild(tdScore);
      tr.appendChild(tdCat);
      tr.appendChild(tdInds);
      tr.appendChild(tdAction);

      historyTbody.appendChild(tr);
    });
  }

  function openInspectModal(record) {
    inspectDomainTitle.textContent = `Telemetry: ${record.domain}`;
    inspectModalBody.innerHTML = `
      <div style="font-size:12px; font-family:var(--font-mono); color:var(--text-secondary); margin-bottom:8px;">
        <div><strong>Event ID:</strong> ${record.id || 'N/A'}</div>
        <div><strong>Timestamp:</strong> ${new Date(record.timestamp).toLocaleString()}</div>
        <div style="word-break:break-all;"><strong>URL:</strong> ${record.url}</div>
      </div>

      <div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
        <span class="category-pill pill-${getSeverityClass(record.riskScore)}">${record.riskCategory} (${record.riskScore}/100)</span>
        <span style="font-size:12px; color:var(--text-secondary);">Confidence: ${record.confidence || 'Medium'}</span>
      </div>

      <div style="font-weight:700; font-size:11px; text-transform:uppercase; color:var(--accent-cyan); margin-bottom:4px;">Recommended Next Action</div>
      <div style="background:var(--bg-card); padding:8px 12px; border-radius:6px; font-size:12px; margin-bottom:12px;">
        ${record.recommendedAction || 'Normal browsing'}
      </div>

      <div style="font-weight:700; font-size:11px; text-transform:uppercase; color:var(--accent-cyan); margin-bottom:4px;">Detection Reasons</div>
      <ul style="background:var(--bg-card); padding:10px 18px; border-radius:6px; font-size:12px; margin-bottom:12px; color:var(--text-secondary);">
        ${(record.reasons && record.reasons.length > 0) 
          ? record.reasons.map(r => `<li style="margin-bottom:4px;">${r}</li>`).join('') 
          : '<li>No security anomalies detected.</li>'}
      </ul>

      <div style="font-weight:700; font-size:11px; text-transform:uppercase; color:var(--accent-cyan); margin-bottom:4px;">Evaluated Indicators</div>
      <div style="display:flex; flex-direction:column; gap:6px;">
        ${(record.indicators && record.indicators.length > 0)
          ? record.indicators.map(i => `
            <div style="background:var(--bg-card); border-left:3px solid var(--accent-cyan); padding:6px 10px; border-radius:4px; font-size:11px;">
              <div style="font-weight:600; color:#fff;">${i.name} <span style="color:var(--text-muted);">(${i.severity})</span></div>
              <div style="color:var(--text-secondary);">${i.description}</div>
            </div>
          `).join('')
          : '<div style="font-size:12px; color:var(--color-low);">Clean baseline. Zero indicators triggered.</div>'}
      </div>
    `;

    inspectModal.classList.remove('hidden');
  }

  btnCloseInspect.addEventListener('click', () => {
    inspectModal.classList.add('hidden');
  });

  inspectModal.addEventListener('click', (e) => {
    if (e.target === inspectModal) inspectModal.classList.add('hidden');
  });

  function sanitizeCsvCell(val) {
    if (val === null || val === undefined) return '""';
    let str = String(val);
    // Protect against spreadsheet formula injection (=, +, -, @, tab, CR)
    if (/^[=+\-@\t\r]/.test(str)) {
      str = "'" + str;
    }
    return `"${str.replace(/"/g, '""')}"`;
  }

  // Export CSV
  btnExportCsv.addEventListener('click', () => {
    if (allHistory.length === 0) {
      showToast('No history records to export');
      return;
    }

    const headers = ['Event ID', 'Timestamp', 'Domain', 'Full URL', 'Risk Score', 'Risk Category', 'Confidence', 'Indicators', 'Reasons', 'Recommended Action'];
    const rows = allHistory.map(rec => [
      sanitizeCsvCell(rec.id || ''),
      sanitizeCsvCell(rec.timestamp || ''),
      sanitizeCsvCell(rec.domain || ''),
      sanitizeCsvCell(rec.url || ''),
      rec.riskScore || 0,
      sanitizeCsvCell(rec.riskCategory || ''),
      sanitizeCsvCell(rec.confidence || ''),
      sanitizeCsvCell((rec.indicators || []).map(i => i.name).join('; ')),
      sanitizeCsvCell((rec.reasons || []).join('; ')),
      sanitizeCsvCell(rec.recommendedAction || '')
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `cybersentry_scan_history_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('Scan History Exported as CSV');
  });

  // Clear History Modal
  btnClearHistory.addEventListener('click', () => {
    confirmModal.classList.remove('hidden');
  });

  btnCancelClear.addEventListener('click', () => {
    confirmModal.classList.add('hidden');
  });

  confirmModal.addEventListener('click', (e) => {
    if (e.target === confirmModal) confirmModal.classList.add('hidden');
  });

  btnConfirmClear.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
    allHistory = [];
    confirmModal.classList.add('hidden');
    updateStats(allHistory);
    renderTable();
    showToast('Scan History Cleared');
  });

  // Filter events
  inputSearch.addEventListener('input', renderTable);
  selectFilter.addEventListener('change', renderTable);
  selectSort.addEventListener('change', renderTable);

  // Load Initial History
  async function loadHistory() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'GET_HISTORY' });
      if (resp && resp.data) {
        allHistory = resp.data;
        updateStats(allHistory);
        renderTable();
      }
    } catch (err) {
      console.warn('[SentinelX History] Load error:', err);
    }
  }

  loadHistory();
});

