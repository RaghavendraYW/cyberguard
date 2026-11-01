/**
 * CyberGuard v2.0 — Notification Center
 * Polls /api/notifications/recent, renders the bell dropdown,
 * and handles dark/light mode toggle.
 */

// ── Notification Center ───────────────────────────────────────
let _notifPanelOpen = false;
let _notifPollTimer = null;

function initNotifications() {
  refreshNotifications();
  // Poll every 30 seconds
  _notifPollTimer = setInterval(refreshNotifications, 30000);

  // Close panel on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.notif-wrap')) {
      closeNotifPanel();
    }
  });
}

async function refreshNotifications() {
  const token = localStorage.getItem('TOKEN');
  if (!token) return;
  try {
    const res = await fetch('/api/notifications/recent?limit=8', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!res.ok) return;
    const data = await res.json();
    renderNotifBadge(data.unread || 0);
    renderNotifPanel(data.notifications || []);

    // Update topbar alert dot too
    const dot = document.getElementById('alertDot');
    if (dot) dot.textContent = data.unread || 0;
  } catch (e) {
    console.warn('Notification fetch failed:', e);
  }
}

function renderNotifBadge(count) {
  let badge = document.getElementById('notifBadge');
  if (!badge) return;
  badge.textContent = count > 99 ? '99+' : count;
  badge.style.display = count > 0 ? 'flex' : 'none';
}

function renderNotifPanel(notifications) {
  const panel = document.getElementById('notifPanel');
  if (!panel) return;

  if (!notifications.length) {
    panel.querySelector('.notif-body').innerHTML = `<div class="notif-empty">🎉 No new critical alerts</div>`;
    return;
  }

  const html = notifications.map(n => `
    <div class="notif-item" onclick="goPage('alerts',document.querySelector('[data-page=alerts]'));closeNotifPanel()">
      <div class="notif-sev-dot ${n.severity}"></div>
      <div style="flex:1;min-width:0">
        <div class="notif-title">${_esc(n.title)}</div>
        <div class="notif-time">${_relTime(n.createdAt)} · ${_esc(n.category)}</div>
      </div>
      <span class="chip chip-${n.severity === 'critical' ? 'crit' : 'hi'}" style="flex-shrink:0;font-size:9px">${n.severity.toUpperCase()}</span>
    </div>
  `).join('');

  panel.querySelector('.notif-body').innerHTML = html;
}

function toggleNotifPanel() {
  const panel = document.getElementById('notifPanel');
  if (!panel) return;
  _notifPanelOpen = !_notifPanelOpen;
  panel.classList.toggle('open', _notifPanelOpen);
  if (_notifPanelOpen) refreshNotifications();
}

function closeNotifPanel() {
  _notifPanelOpen = false;
  const panel = document.getElementById('notifPanel');
  if (panel) panel.classList.remove('open');
}


// ── Dark / Light Mode Toggle ──────────────────────────────────
function initTheme() {
  const saved = localStorage.getItem('CG_THEME') || 'dark';
  applyTheme(saved, false);
}

function toggleTheme() {
  const isDark = !document.body.classList.contains('light-mode');
  const next = isDark ? 'light' : 'dark';
  applyTheme(next, true);

  // Persist to backend preferences if logged in
  const token = localStorage.getItem('TOKEN');
  if (token) {
    fetch('/api/preferences', {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme: next })
    }).catch(() => {});
  }
}

function applyTheme(theme, animate) {
  const body = document.body;
  const btn  = document.getElementById('themeToggleBtn');
  if (animate) body.style.transition = 'background 0.3s, color 0.3s';

  if (theme === 'light') {
    body.classList.add('light-mode');
    if (btn) btn.innerHTML = '☀️ Light';
  } else {
    body.classList.remove('light-mode');
    if (btn) btn.innerHTML = '🌙 Dark';
  }
  localStorage.setItem('CG_THEME', theme);

  if (animate) setTimeout(() => body.style.transition = '', 400);
}


// ── Relative Time ─────────────────────────────────────────────
function _relTime(iso) {
  if (!iso) return '';
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function _esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}


// ── Breadcrumb ────────────────────────────────────────────────
function updateBreadcrumb(pageLabel) {
  const bc = document.getElementById('breadcrumb');
  if (!bc) return;
  bc.innerHTML = `
    <span class="breadcrumb-item" onclick="goPage('dashboard',document.querySelector('[data-page=dashboard]'))">Home</span>
    <span class="breadcrumb-sep">›</span>
    <span class="breadcrumb-current">${pageLabel || 'Dashboard'}</span>
  `;
}


// ── Pagination Helper ─────────────────────────────────────────
/**
 * PaginationController — attach to any list that supports skip/limit
 * Usage: new PaginationController({ containerId, fetchFn, renderFn, pageSize })
 */
class PaginationController {
  constructor({ containerId, paginationId, fetchFn, renderFn, pageSize = 25 }) {
    this.containerId  = containerId;
    this.paginationId = paginationId;
    this.fetchFn  = fetchFn;
    this.renderFn = renderFn;
    this.pageSize = pageSize;
    this.page     = 0;
    this.total    = 0;
    this._perPageEl = null;
  }

  get skip() { return this.page * this.pageSize; }
  get totalPages() { return Math.max(1, Math.ceil(this.total / this.pageSize)); }

  async load() {
    const data = await this.fetchFn(this.skip, this.pageSize);
    if (data.total !== undefined) this.total = data.total;
    this.renderFn(data);
    this._renderControls();
  }

  _renderControls() {
    const el = document.getElementById(this.paginationId);
    if (!el) return;
    const from = this.total === 0 ? 0 : this.skip + 1;
    const to   = Math.min(this.skip + this.pageSize, this.total);

    el.innerHTML = `
      <span style="color:var(--text3)">Showing ${from}–${to} of ${this.total}</span>
      <div class="pagination-pages">
        <button class="page-btn" onclick="_pgCtrl_${this.containerId}.prev()" ${this.page === 0 ? 'disabled' : ''}>‹</button>
        ${this._pageNumbers().map(p => p === '…'
          ? `<span style="color:var(--text3);padding:0 4px">…</span>`
          : `<button class="page-btn ${p === this.page ? 'active' : ''}" onclick="_pgCtrl_${this.containerId}.goTo(${p})">${p+1}</button>`
        ).join('')}
        <button class="page-btn" onclick="_pgCtrl_${this.containerId}.next()" ${this.page >= this.totalPages-1 ? 'disabled' : ''}>›</button>
      </div>
      <select class="per-page-select" onchange="_pgCtrl_${this.containerId}.setPageSize(+this.value)">
        ${[10,25,50,100].map(n => `<option value="${n}" ${n===this.pageSize?'selected':''}>${n} / page</option>`).join('')}
      </select>
    `;
    // register globally so onclick can find it
    window[`_pgCtrl_${this.containerId}`] = this;
  }

  _pageNumbers() {
    const pages = [];
    const total = this.totalPages;
    if (total <= 7) {
      for (let i = 0; i < total; i++) pages.push(i);
    } else {
      pages.push(0);
      if (this.page > 2) pages.push('…');
      for (let i = Math.max(1, this.page-1); i <= Math.min(total-2, this.page+1); i++) pages.push(i);
      if (this.page < total-3) pages.push('…');
      pages.push(total-1);
    }
    return pages;
  }

  async prev()  { if (this.page > 0) { this.page--; await this.load(); } }
  async next()  { if (this.page < this.totalPages-1) { this.page++; await this.load(); } }
  async goTo(p) { this.page = p; await this.load(); }
  async setPageSize(n) { this.pageSize = n; this.page = 0; await this.load(); }
  async reset() { this.page = 0; await this.load(); }
}

window.PaginationController = PaginationController;


// ── Skeleton Loader ───────────────────────────────────────────
function showSkeleton(containerId, rows = 5, cols = 4) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const cells = Array(cols).fill('<td><div class="skeleton skeleton-row full"></div></td>').join('');
  el.innerHTML = Array(rows).fill(`<tr class="skeleton-table">${cells}</tr>`).join('');
}

function showCardSkeleton(containerId, count = 3) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = Array(count).fill(`
    <div class="card skeleton-card">
      <div class="skeleton skeleton-row short"></div>
      <div class="skeleton skeleton-row full"></div>
      <div class="skeleton skeleton-row medium"></div>
    </div>
  `).join('');
}

window.showSkeleton     = showSkeleton;
window.showCardSkeleton = showCardSkeleton;
window.initNotifications  = initNotifications;
window.refreshNotifications = refreshNotifications;
window.toggleNotifPanel   = toggleNotifPanel;
window.closeNotifPanel    = closeNotifPanel;
window.initTheme  = initTheme;
window.toggleTheme = toggleTheme;
window.updateBreadcrumb = updateBreadcrumb;
