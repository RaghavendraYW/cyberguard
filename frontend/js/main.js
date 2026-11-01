// CyberGuard v2.0 — Startup & Bootstrap (Enterprise)
document.addEventListener('DOMContentLoaded', function () {
  // Support ENTER key on login form
  document.getElementById('loginPass')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLogin();
  });
  document.getElementById('loginEmail')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('loginPass')?.focus();
  });

  const activeSession = sessionStorage.getItem('cg_authenticated');
  const savedToken    = localStorage.getItem('cg_token') || localStorage.getItem('TOKEN');
  const savedUser     = localStorage.getItem('cg_user');

  if (activeSession === '1' && savedToken && savedUser) {
    try {
      TOKEN        = savedToken;
      CURRENT_USER = JSON.parse(savedUser);
      showApp();
      initApp().then(() => {
        if (typeof startBadgePolling === 'function') startBadgePolling();
        if (typeof updateAttackSurfaceStats === 'function') updateAttackSurfaceStats();
        initGlobalSearch();
      }).catch(() => {});
    } catch (e) {
      clearSession();
    }
  } else {
    // Show login page first
    showLogin();
  }
});

function showApp() {
  document.getElementById('loginPage').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
}

function showLogin() {
  TOKEN = '';
  CURRENT_USER = null;
  const lp = document.getElementById('loginPage');
  const ap = document.getElementById('app');
  if (lp) lp.style.display = 'flex';
  if (ap) ap.style.display = 'none';

  const emailInp = document.getElementById('loginEmail');
  const passInp  = document.getElementById('loginPass');
  const errEl    = document.getElementById('loginError');
  if (emailInp && !emailInp.value) emailInp.value = 'admin@company.com';
  if (passInp && !passInp.value)   passInp.value  = 'Admin@1234';
  if (errEl) errEl.style.display = 'none';
}

function clearSession() {
  TOKEN = '';
  CURRENT_USER = null;
  localStorage.clear();
  sessionStorage.clear();
  showLogin();
}

// ── Global Search Expansion (Vendors, Alerts, Leaks, Questionnaires, Reports) ──
function initGlobalSearch() {
  const inp = document.getElementById('globalSearch');
  if (!inp) return;

  const wrap = inp.closest('.search-wrap');
  let dropdown = document.getElementById('globalSearchDropdown');
  if (!dropdown && wrap) {
    dropdown = document.createElement('div');
    dropdown.id = 'globalSearchDropdown';
    dropdown.style.display = 'none';
    wrap.appendChild(dropdown);
  }

  let debounceTimer = null;
  inp.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    const q = inp.value.trim().toLowerCase();
    if (q.length < 2) {
      if (dropdown) dropdown.style.display = 'none';
      return;
    }
    debounceTimer = setTimeout(() => runGlobalSearch(q, dropdown), 200);
  });

  document.addEventListener('click', (e) => {
    if (wrap && !wrap.contains(e.target) && dropdown) {
      dropdown.style.display = 'none';
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && dropdown) {
      dropdown.style.display = 'none';
    }
  });
}

async function runGlobalSearch(q, dropdown) {
  if (!dropdown) return;
  dropdown.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text3);"><div class="spinner"></div></div>';
  dropdown.style.display = 'block';

  try {
    const [vRes, aRes, lRes, qRes, rRes] = await Promise.all([
      api('GET', `/vendors/?search=${encodeURIComponent(q)}&limit=5`).catch(() => ({ vendors: [] })),
      api('GET', `/alerts/?limit=30`).catch(() => ({ alerts: [] })),
      api('GET', `/leaks/`).catch(() => ({ leaks: [] })),
      api('GET', `/questionnaires/`).catch(() => ({ questionnaires: [] })),
      api('GET', `/reports/?limit=30`).catch(() => ({ reports: [] }))
    ]);

    const vendors = (vRes.vendors || []).slice(0, 4);
    const alerts = (aRes.alerts || []).filter(a => (a.title || '').toLowerCase().includes(q) || (a.category || '').toLowerCase().includes(q)).slice(0, 4);
    const leaks = (lRes.leaks || []).filter(l => (l.title || '').toLowerCase().includes(q) || (l.source || '').toLowerCase().includes(q)).slice(0, 3);
    const questionnaires = (qRes.questionnaires || []).filter(item => (item.title || '').toLowerCase().includes(q) || (item.framework || '').toLowerCase().includes(q)).slice(0, 3);
    const reports = (rRes.reports || []).filter(r => (r.title || '').toLowerCase().includes(q) || (r.type || '').toLowerCase().includes(q)).slice(0, 3);

    const hasResults = vendors.length || alerts.length || leaks.length || questionnaires.length || reports.length;
    if (!hasResults) {
      dropdown.innerHTML = '<div style="padding:20px;text-align:center;font-size:12px;color:var(--text3);">No matching items found for "' + q + '"</div>';
      return;
    }

    let html = '';
    if (vendors.length) {
      html += '<div class="search-category-title">🏢 Vendors</div>';
      vendors.forEach(v => {
        html += `<div class="search-result-item" onclick="onSearchResultClick('vendors', ${v.id})">
          <div><div class="search-result-title">${v.name}</div><div class="search-result-sub">${v.domain} · ${v.category}</div></div>
          <span class="chip chip-${v.risk}">${v.score}</span>
        </div>`;
      });
    }

    if (alerts.length) {
      html += '<div class="search-category-title">🚨 Alerts</div>';
      alerts.forEach(a => {
        html += `<div class="search-result-item" onclick="onSearchResultClick('alerts', ${a.id})">
          <div><div class="search-result-title">${a.title}</div><div class="search-result-sub">${a.category} · ${a.status}</div></div>
          <span class="chip chip-${a.severity}">${a.severity}</span>
        </div>`;
      });
    }

    if (leaks.length) {
      html += '<div class="search-category-title">💧 Data Leaks</div>';
      leaks.forEach(l => {
        html += `<div class="search-result-item" onclick="onSearchResultClick('leaks', ${l.id})">
          <div><div class="search-result-title">${l.title}</div><div class="search-result-sub">${l.source} · ${l.credentials} credentials</div></div>
          <span class="chip chip-${l.severity}">${l.status}</span>
        </div>`;
      });
    }

    if (questionnaires.length) {
      html += '<div class="search-category-title">📋 Questionnaires</div>';
      questionnaires.forEach(item => {
        html += `<div class="search-result-item" onclick="onSearchResultClick('questionnaires', ${item.id})">
          <div><div class="search-result-title">${item.title}</div><div class="search-result-sub">${item.framework} · ${item.status}</div></div>
          <span class="chip chip-info">${item.answered}/${item.total}</span>
        </div>`;
      });
    }

    if (reports.length) {
      html += '<div class="search-category-title">📄 Reports</div>';
      reports.forEach(r => {
        html += `<div class="search-result-item" onclick="onSearchResultClick('reports', ${r.id})">
          <div><div class="search-result-title">${r.title}</div><div class="search-result-sub">${r.type} · ${r.date}</div></div>
          <span class="chip chip-ok">${r.pages}p</span>
        </div>`;
      });
    }

    dropdown.innerHTML = html;
  } catch (e) {
    dropdown.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text3);">Search error: ' + (e.message || "Unknown") + '</div>';
  }
}

function onSearchResultClick(page, id) {
  const dropdown = document.getElementById('globalSearchDropdown');
  if (dropdown) dropdown.style.display = 'none';
  const inp = document.getElementById('globalSearch');
  if (inp) inp.value = '';

  const nav = document.querySelector(`[data-page="${page}"]`);
  if (nav && typeof goPage === 'function') {
    goPage(page, nav);
  }
}
