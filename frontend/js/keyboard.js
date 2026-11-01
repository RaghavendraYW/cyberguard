/**
 * CyberGuard v2.0 — Keyboard Shortcuts
 * GitHub-style chord shortcuts (press G then a letter).
 * Also handles ? to open the shortcut reference overlay.
 */
(function () {
  'use strict';

  const SHORTCUTS = [
    { keys: ['g', 'd'], label: 'Go to Dashboard',         page: 'dashboard'    },
    { keys: ['g', 'v'], label: 'Go to Vendor Risk',       page: 'vendors'      },
    { keys: ['g', 'a'], label: 'Go to Alerts',            page: 'alerts'       },
    { keys: ['g', 'l'], label: 'Go to Data Leaks',        page: 'leaks'        },
    { keys: ['g', 'b'], label: 'Go to BreachSight',       page: 'breachsight'  },
    { keys: ['g', 'm'], label: 'Go to ML Anomalies',      page: 'anomalies'    },
    { keys: ['g', 'i'], label: 'Go to Insider Detection', page: 'insider'      },
    { keys: ['g', 'c'], label: 'Go to Compliance',        page: 'compliance'   },
    { keys: ['g', 'r'], label: 'Go to Reports',           page: 'reports'      },
    { keys: ['g', 's'], label: 'Go to Settings',          page: 'settings'     },
  ];

  const SINGLE_KEYS = [
    { key: '?',      label: 'Show keyboard shortcuts' },
    { key: 'Escape', label: 'Close modal / overlay' },
    { key: '/',      label: 'Focus global search' },
  ];

  let pendingG = false;
  let gTimer   = null;
  let overlayEl = null;

  function clearG() {
    pendingG = false;
    if (gTimer) { clearTimeout(gTimer); gTimer = null; }
  }

  function goToPage(page) {
    const el = document.querySelector(`[data-page="${page}"]`);
    if (el && typeof goPage === 'function') {
      goPage(page, el);
    }
  }

  function showOverlay() {
    if (overlayEl) return;
    overlayEl = document.createElement('div');
    overlayEl.className = 'shortcuts-overlay';
    overlayEl.innerHTML = `
      <div class="shortcuts-panel">
        <div class="shortcuts-title">
          <span>⌨️ Keyboard Shortcuts</span>
          <span style="font-size:11px;color:var(--text3);cursor:pointer" onclick="closeShortcutsOverlay()">✕ ESC</span>
        </div>
        <div class="shortcuts-grid">
          ${SHORTCUTS.map(s => `
            <div class="shortcut-row">
              <span>${s.label}</span>
              <span class="kbd-hint">
                <span class="kbd">${s.keys[0].toUpperCase()}</span>
                <span style="color:var(--text3);font-size:10px">then</span>
                <span class="kbd">${s.keys[1].toUpperCase()}</span>
              </span>
            </div>
          `).join('')}
          <div style="border-top:1px solid var(--border);margin:8px 0;"></div>
          ${SINGLE_KEYS.map(s => `
            <div class="shortcut-row">
              <span>${s.label}</span>
              <span class="kbd-hint"><span class="kbd">${s.key === 'Escape' ? 'Esc' : s.key}</span></span>
            </div>
          `).join('')}
        </div>
      </div>`;
    document.body.appendChild(overlayEl);
    overlayEl.addEventListener('click', (e) => {
      if (e.target === overlayEl) closeShortcutsOverlay();
    });
  }

  window.closeShortcutsOverlay = function () {
    if (overlayEl) { overlayEl.remove(); overlayEl = null; }
  };

  document.addEventListener('keydown', (e) => {
    const tag = (e.target.tagName || '').toLowerCase();
    const editing = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable;

    // ESC — close overlay or any open modal
    if (e.key === 'Escape') {
      if (overlayEl) { closeShortcutsOverlay(); return; }
      // close any open modal
      document.querySelectorAll('.modal-overlay[style*="flex"], .modal-overlay[style*="block"]').forEach(m => {
        m.style.display = 'none';
      });
      clearG();
      return;
    }

    if (editing) { clearG(); return; }

    // ? — show shortcuts overlay
    if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      overlayEl ? closeShortcutsOverlay() : showOverlay();
      return;
    }

    // / — focus search
    if (e.key === '/' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      const search = document.getElementById('globalSearch');
      if (search) search.focus();
      return;
    }

    const k = e.key.toLowerCase();

    if (pendingG) {
      clearG();
      const match = SHORTCUTS.find(s => s.keys[0] === 'g' && s.keys[1] === k);
      if (match) {
        e.preventDefault();
        goToPage(match.page);
      }
      return;
    }

    if (k === 'g' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      pendingG = true;
      gTimer = setTimeout(clearG, 1500);
    }
  });
})();
