// CyberGuard v2.0 — Settings (Enterprise)
// Loads profile + preferences, saves both with backend persistence.
// Audit log viewer shows last 20 actions by the logged-in user.

function loadSettings() {
  if (!CURRENT_USER) return;
  document.getElementById('set-name').value    = CURRENT_USER.name    || '';
  document.getElementById('set-email').value   = CURRENT_USER.email   || '';
  document.getElementById('set-role').value    = CURRENT_USER.role    || '';
  document.getElementById('set-company').value = CURRENT_USER.company || '';
  document.getElementById('set-domain').value  = CURRENT_USER.domain  || '';

  // Restore prefs from cached window._userPrefs
  if (window._userPrefs) {
    applyPrefsToSettings(window._userPrefs);
    const threshold = document.getElementById('anomaly-threshold');
    const label     = document.getElementById('anomaly-threshold-val');
    if (threshold && window._userPrefs.anomalyThreshold) {
      threshold.value = window._userPrefs.anomalyThreshold;
      if (label) label.textContent = parseFloat(window._userPrefs.anomalyThreshold).toFixed(2);
    }
  }

  // Load audit log
  loadSettingsAuditLog();
}

// ── Profile save ──────────────────────────────────────────────
async function saveSettings() {
  const body = {
    name:    document.getElementById('set-name').value,
    role:    document.getElementById('set-role').value,
    company: document.getElementById('set-company').value,
    domain:  document.getElementById('set-domain').value,
  };
  const pw = document.getElementById('set-password').value;
  if (pw) body.password = pw;

  try {
    const d = await api('PUT', '/auth/update', body);
    CURRENT_USER = d;
    localStorage.setItem('cg_user', JSON.stringify(d));
    const av = document.getElementById('userAv');
    const nm = document.getElementById('userName');
    const rl = document.getElementById('userRole');
    if (av) av.textContent = d.initials;
    if (nm) nm.textContent = d.name;
    if (rl) rl.textContent = d.role;
    // Clear password field after save
    document.getElementById('set-password').value = '';
    showSaveIndicator('profileSaved');
    toast('Profile saved ✓', 'success');
  } catch (e) {
    toast('Save failed: ' + (e.message || 'Unknown error'), 'error');
  }
}

// ── Preferences save ──────────────────────────────────────────
async function savePreferences() {
  const body = {
    notif_critical:    document.getElementById('notif-critical-toggle')?.checked ?? true,
    notif_leaks:       document.getElementById('notif-leaks-toggle')?.checked    ?? true,
    notif_ml:          document.getElementById('notif-ml-toggle')?.checked       ?? true,
    ml_autotrain:      document.getElementById('ml-autotrain-toggle')?.checked   ?? true,
    ml_vendorscan:     document.getElementById('ml-vendorscan-toggle')?.checked  ?? true,
    anomaly_threshold: parseFloat(document.getElementById('anomaly-threshold')?.value || '0.7'),
  };
  try {
    const prefs = await api('PUT', '/preferences', body);
    window._userPrefs = prefs;
    showSaveIndicator('prefsSaved');
    toast('Preferences saved ✓', 'success');
  } catch (e) {
    toast('Failed to save preferences', 'error');
  }
}

// ── Toggle auto-save (called by onchange on each toggle) ──────
async function togglePref(key) {
  const elId = key.replace(/_/g, '-') + '-toggle';
  const el   = document.getElementById(elId)
             || document.getElementById(key + '-toggle')
             || document.getElementById(key);

  // Special case: range input for threshold
  if (key === 'anomaly_threshold') {
    const rangeEl = document.getElementById('anomaly-threshold');
    if (!rangeEl) return;
    const val = parseFloat(rangeEl.value);
    try {
      const prefs = await api('PUT', '/preferences', { anomaly_threshold: val });
      window._userPrefs = { ...(window._userPrefs || {}), ...prefs };
      showSaveIndicator('prefsSaved');
    } catch(e) { /* ignore */ }
    return;
  }

  if (!el) return;
  const val = el.checked;

  // Convert kebab-key to snake_key for backend
  const snakeKey = key.replace(/-/g, '_');
  const body = {};
  body[snakeKey] = val;

  try {
    const prefs = await api('PUT', '/preferences', body);
    window._userPrefs = { ...(window._userPrefs || {}), ...prefs };
    showSaveIndicator('prefsSaved');
  } catch(e) {
    // Revert toggle on failure
    if (el && el.type === 'checkbox') el.checked = !val;
    toast('Failed to save preference', 'error');
  }
}

// ── Audit Log Viewer ──────────────────────────────────────────
async function loadSettingsAuditLog() {
  const el = document.getElementById('settingsAuditLog');
  if (!el || !CURRENT_USER) return;

  try {
    const d = await api('GET', `/logs/?email=${encodeURIComponent(CURRENT_USER.email)}&limit=20&skip=0`);
    const logs = d.logs || [];
    if (!logs.length) {
      el.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text3);font-size:12px;">No activity recorded yet.</div>';
      return;
    }
    const actionIcon = {
      login:'🔐', logout:'👋', view_dashboard:'📊', export_report:'📤',
      add_vendor:'➕', scan_domain:'🔍', access_settings:'⚙️', view_vendor:'👁️',
      update_alert:'🔔', delete_alert:'🗑️', download_report:'⬇️'
    };
    el.innerHTML = logs.map(l => {
      const icon = actionIcon[l.action] || '📝';
      const ts   = l.timestamp ? new Date(l.timestamp).toLocaleString() : '—';
      const anomBadge = l.isAnomaly
        ? `<span style="font-size:9px;background:rgba(244,63,94,0.15);color:var(--red);padding:1px 5px;border-radius:3px;margin-left:6px;">ANOMALY</span>`
        : '';
      return `<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:6px;background:var(--surf2);border:1px solid var(--border);">
        <span style="font-size:12px;">${icon}</span>
        <div style="flex:1;min-width:0;">
          <span style="font-size:11px;font-weight:600;">${(l.action||'').replace(/_/g,' ')}</span>
          ${anomBadge}
          <span style="font-size:10px;color:var(--text3);margin-left:4px;">· ${l.ipAddress || ''}</span>
        </div>
        <span style="font-size:10px;color:var(--text3);white-space:nowrap;flex-shrink:0;">${ts}</span>
      </div>`;
    }).join('');
  } catch (e) {
    el.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text3);font-size:12px;">Unable to load activity log.</div>';
  }
}

// ── Save indicator ────────────────────────────────────────────
function showSaveIndicator(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.add('visible');
  setTimeout(() => el.classList.remove('visible'), 2000);
}
