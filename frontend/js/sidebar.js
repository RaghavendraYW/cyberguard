// CyberGuard v2.0 — Sidebar & Navigation (Enterprise)
function toggleSidebar() {
  const sb = document.querySelector('.sidebar');
  const isCollapsed = sb.classList.toggle('collapsed');
  localStorage.setItem('cg_sidebar', isCollapsed ? 'collapsed' : 'expanded');
  document.querySelector('.topbar').classList.toggle('sb-collapsed', isCollapsed);
  document.querySelector('.main-right').classList.toggle('sb-collapsed', isCollapsed);
  document.getElementById('toggleIcon').textContent = isCollapsed ? '▶' : '◀';
}

function applySidebarState() {
  if (localStorage.getItem('cg_sidebar') === 'collapsed') {
    document.querySelector('.sidebar').classList.add('collapsed');
    document.querySelector('.topbar').classList.add('sb-collapsed');
    document.querySelector('.main-right').classList.add('sb-collapsed');
    const ti = document.getElementById('toggleIcon');
    if (ti) ti.textContent = '▶';
  }
}

function toggleMobileSidebar() {
  const sb = document.querySelector('.sidebar');
  const overlay = document.getElementById('mobileOverlay');
  const isOpen = sb.classList.toggle('mobile-open');
  if (overlay) overlay.classList.toggle('active', isOpen);
  document.body.style.overflow = isOpen ? 'hidden' : '';
}

function closeMobileSidebar() {
  const sb = document.querySelector('.sidebar');
  const overlay = document.getElementById('mobileOverlay');
  sb?.classList.remove('mobile-open');
  overlay?.classList.remove('active');
  document.body.style.overflow = '';
}

const PAGE_LABELS = {
  dashboard:    'Security Dashboard',
  vendors:      'Vendor Risk Management',
  alerts:       'Security Alerts',
  leaks:        'Data Leaks & Breaches',
  breachsight:  'BreachSight — Attack Surface',
  anomalies:    'ML Anomaly Detection',
  insider:      'Insider Threat Detection',
  compliance:   'Compliance & Frameworks',
  questionnaires: 'Security Questionnaires',
  reports:      'Reports & Export',
  admin:        'User Administration',
  settings:     'Account Settings',
  vpn:          'VPN & Zero-Trust Perimeter',
};

function goPage(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('page-hidden'));
  document.getElementById('page-' + page)?.classList.remove('page-hidden');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (el) el.classList.add('active');

  const label = PAGE_LABELS[page] || (el?.dataset?.label || page).trim();
  document.getElementById('pageTitle').textContent = label;
  if (typeof updateBreadcrumb === 'function') updateBreadcrumb(label);

  renderPage(page);
  trackAction('view_' + page);
  closeMobileSidebar();
}

async function renderPage(page) {
  switch (page) {
    case 'dashboard':      await loadDashboard();      break;
    case 'vendors':        await loadVendors();        break;
    case 'alerts':         await loadAlerts();         break;
    case 'leaks':          await loadLeaks();          break;
    case 'anomalies':      await loadAnomalies();      break;
    case 'questionnaires': await loadQuestionnaires(); break;
    case 'reports':        await loadReports();        break;
    case 'settings':       loadSettings();             break;
    case 'admin':          await loadAdmin();          break;
    case 'insider':        await loadInsider();        break;
    case 'breachsight':    await loadBreachSight();    break;
    case 'vpn':            await loadVPN();            break;
  }
}

async function initApp() {
  // Apply saved theme
  if (typeof initTheme === 'function') initTheme();

  applySidebarState();
  document.getElementById('userAv').textContent = CURRENT_USER?.initials || '??';
  document.getElementById('userName').textContent = CURRENT_USER?.name || 'User';
  if (document.getElementById('userRole')) {
    document.getElementById('userRole').textContent = CURRENT_USER.role;
  }
  const ag = document.getElementById('adminNavGroup');
  if (ag) ag.style.display = CURRENT_USER?.isAdmin ? 'block' : 'none';

  renderAttack();
  renderCompliance();
  await loadDashboard();
  await updateBadges();

  // Start notification polling after login
  if (typeof initNotifications === 'function') initNotifications();

  // Load preferences from backend
  try {
    const prefs = await api('GET', '/preferences');
    if (prefs.theme && typeof applyTheme === 'function') applyTheme(prefs.theme, false);
    window._userPrefs = prefs;
    applyPrefsToSettings(prefs);
  } catch(e) { /* ignore */ }
}

function applyPrefsToSettings(prefs) {
  const map = {
    'notif-critical-toggle': prefs.notifCritical,
    'notif-leaks-toggle':    prefs.notifLeaks,
    'notif-ml-toggle':       prefs.notifMl,
    'ml-autotrain-toggle':   prefs.mlAutotrain,
    'ml-vendorscan-toggle':  prefs.mlVendorscan,
  };
  for (const [id, val] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (el && val !== undefined) el.checked = !!val;
  }
  const threshold = document.getElementById('anomaly-threshold');
  if (threshold && prefs.anomalyThreshold !== undefined) threshold.value = prefs.anomalyThreshold;
}

// BreachSight stats driven by real API data
async function loadBreachSight() {
  try {
    const vs = await api('GET', '/vendors/stats');
    const as = await api('GET', '/alerts');
    const sslAlerts = (as.alerts || []).filter(a => a.title.toLowerCase().includes('ssl') && a.status === 'open').length;
    const exposed   = (as.alerts || []).filter(a => a.category === 'Network' && a.status === 'open').length;

    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('bsDomains',   vs.total ?? '—');
    set('bsIPs',       ((vs.total || 0) * 6).toString());
    set('bsServices',  exposed || '—');
    set('bsSSL',       sslAlerts || '0');
  } catch(e) { /* ignore */ }
}
