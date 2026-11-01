/**
 * CyberGuard v3.0 — Threat Detection Dashboard
 * Replaces the active-window surveillance view with:
 *   - Live threat event feed (MITRE ATT&CK tagged)
 *   - Per-user risk scoreboard
 *   - Fleet device posture health grid
 *   - Employee self-service (own events + transparency)
 */

/* ─── MITRE Technique labels ─────────────────────────────── */
const MITRE_LABELS = {
  "T1110":     "T1110 · Brute Force",
  "T1078":     "T1078 · Valid Accounts",
  "T1133":     "T1133 · External Remote Services",
  "T1562":     "T1562 · Impair Defenses",
  "T1048":     "T1048 · Exfiltration over Alt Protocol",
  "T1071.004": "T1071.004 · DNS Application Layer Protocol",
  "T1078.002": "T1078.002 · Domain Accounts",
  "T1003":     "T1003 · OS Credential Dumping",
};

/* ─── Severity styling ───────────────────────────────────── */
const SEV_CLASS = {
  critical: "badge-critical",
  high:     "badge-high",
  medium:   "badge-medium",
  low:      "badge-low",
};

const RISK_COLOR = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

/* ─── State ──────────────────────────────────────────────── */
let _threatPollTimer = null;
let _threatFilter    = { severity: null, resolved: false, days: 7 };

/* ═══════════════════════════════════════════════════════════
   THREAT FEED
═══════════════════════════════════════════════════════════ */

async function loadThreatFeed() {
  const container = document.getElementById("threat-feed-container");
  if (!container) return;

  const params = new URLSearchParams({ limit: 50, days: _threatFilter.days, resolved: _threatFilter.resolved });
  if (_threatFilter.severity) params.set("severity", _threatFilter.severity);

  try {
    const res  = await apiGet(`/api/threats/events?${params}`);
    const data = await res.json();
    renderThreatFeed(data.events || [], data.total || 0);
  } catch (e) {
    container.innerHTML = `<div class="empty-state"><p>⚠️ Could not load threat events</p></div>`;
  }
}

function renderThreatFeed(events, total) {
  const container = document.getElementById("threat-feed-container");
  const badge      = document.getElementById("threat-total-badge");
  if (badge) badge.textContent = total;

  if (!events.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <p>No threat events match your filter</p>
      </div>`;
    return;
  }

  container.innerHTML = events.map(ev => `
    <div class="threat-event-card severity-border-${ev.severity}" id="threat-${ev.id}">
      <div class="threat-event-header">
        <div class="threat-meta">
          <span class="badge ${SEV_CLASS[ev.severity] || 'badge-medium'}">${ev.severity.toUpperCase()}</span>
          <span class="mitre-tag" title="${ev.mitre_tactic}">${MITRE_LABELS[ev.mitre_technique] || ev.mitre_technique}</span>
          ${ev.resolved ? '<span class="badge badge-resolved">RESOLVED</span>' : ''}
        </div>
        <span class="threat-time">${formatRelativeTime(ev.created_at)}</span>
      </div>
      <div class="threat-event-body">
        <div class="threat-type-label">${formatEventType(ev.event_type)}</div>
        <p class="threat-details">${escapeHtml(ev.details)}</p>
        <div class="threat-footer">
          <span class="threat-user">👤 ${ev.user_email}</span>
          <span class="threat-source">Source: <code>${ev.source}</code></span>
          <span class="threat-peer">VPN: <code>${ev.peer_ip || 'N/A'}</code></span>
          ${!ev.resolved ? `
            <button class="btn btn-xs btn-outline-success"
                    onclick="resolveEvent(${ev.id})"
                    id="resolve-btn-${ev.id}">
              ✓ Resolve
            </button>` : ''}
        </div>
      </div>
    </div>
  `).join('');
}

async function resolveEvent(eventId) {
  const btn = document.getElementById(`resolve-btn-${eventId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Resolving…"; }
  try {
    await apiPost(`/api/threats/resolve/${eventId}`);
    const card = document.getElementById(`threat-${eventId}`);
    if (card) {
      card.style.opacity = "0.5";
      card.querySelector(".threat-event-header .threat-meta").insertAdjacentHTML(
        "beforeend", '<span class="badge badge-resolved">RESOLVED</span>'
      );
      if (btn) btn.remove();
    }
    showToast("Event resolved ✓", "success");
  } catch {
    showToast("Failed to resolve event", "error");
    if (btn) { btn.disabled = false; btn.textContent = "✓ Resolve"; }
  }
}

/* ═══════════════════════════════════════════════════════════
   RISK SCOREBOARD
═══════════════════════════════════════════════════════════ */

async function loadRiskScores() {
  const container = document.getElementById("risk-scoreboard");
  if (!container) return;

  try {
    const res  = await apiGet("/api/threats/risk-scores");
    const data = await res.json();
    renderRiskScoreboard(data.risk_scores || []);
  } catch {
    container.innerHTML = `<p class="text-muted">Could not load risk scores</p>`;
  }
}

function renderRiskScoreboard(scores) {
  const container = document.getElementById("risk-scoreboard");
  if (!scores.length) {
    container.innerHTML = `<div class="empty-state"><p>No risk data yet</p></div>`;
    return;
  }

  container.innerHTML = `
    <table class="threat-table">
      <thead>
        <tr>
          <th>User</th>
          <th>Role</th>
          <th>Risk Score</th>
          <th>Risk Level</th>
          <th>Open Events</th>
          <th>Device Posture</th>
        </tr>
      </thead>
      <tbody>
        ${scores.map(s => `
          <tr class="${s.risk_level === 'critical' || s.risk_level === 'high' ? 'row-risk-' + s.risk_level : ''}">
            <td><strong>${escapeHtml(s.user_name)}</strong><br><small>${s.user_email}</small></td>
            <td>${escapeHtml(s.role)}</td>
            <td>
              <div class="risk-score-bar-wrap">
                <div class="risk-score-bar" style="width:${s.risk_score}%; background:${RISK_COLOR[s.risk_level]}"></div>
                <span class="risk-score-num">${s.risk_score}/100</span>
              </div>
            </td>
            <td><span class="badge ${SEV_CLASS[s.risk_level] || 'badge-medium'}">${s.risk_level.toUpperCase()}</span></td>
            <td>${s.open_events}</td>
            <td>
              <span class="badge ${SEV_CLASS[s.posture_risk] || 'badge-medium'}">${s.posture_score ?? '–'}/100</span>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>`;
}

/* ═══════════════════════════════════════════════════════════
   FLEET POSTURE GRID
═══════════════════════════════════════════════════════════ */

async function loadFleetPosture() {
  const container = document.getElementById("fleet-posture-grid");
  if (!container) return;

  try {
    const res  = await apiGet("/api/posture/fleet");
    const data = await res.json();
    renderFleetPostureSummary(data.summary);
    renderFleetPostureGrid(data.fleet || []);
  } catch {
    container.innerHTML = `<p class="text-muted">Could not load fleet posture</p>`;
  }
}

function renderFleetPostureSummary(summary) {
  const el = document.getElementById("fleet-posture-summary");
  if (!el || !summary) return;
  el.innerHTML = `
    <div class="posture-stat">
      <div class="posture-stat-value">${summary.total_devices}</div>
      <div class="posture-stat-label">Total Devices</div>
    </div>
    <div class="posture-stat text-success">
      <div class="posture-stat-value">${summary.compliant}</div>
      <div class="posture-stat-label">Compliant</div>
    </div>
    <div class="posture-stat text-danger">
      <div class="posture-stat-value">${summary.failing}</div>
      <div class="posture-stat-label">Failing</div>
    </div>
    <div class="posture-stat">
      <div class="posture-stat-value">${summary.compliance_rate}%</div>
      <div class="posture-stat-label">Compliance Rate</div>
    </div>`;
}

function renderFleetPostureGrid(fleet) {
  const container = document.getElementById("fleet-posture-grid");
  if (!fleet.length) {
    container.innerHTML = `<div class="empty-state"><p>No posture data yet</p></div>`;
    return;
  }

  container.innerHTML = fleet.map(u => `
    <div class="posture-user-card risk-border-${u.fleet_risk}">
      <div class="posture-user-header">
        <div>
          <strong>${escapeHtml(u.user_email)}</strong>
          <span class="badge ${SEV_CLASS[u.fleet_risk] || 'badge-medium'}" style="margin-left:8px">${u.fleet_risk.toUpperCase()}</span>
        </div>
        <span class="posture-avg-score" style="color:${RISK_COLOR[u.fleet_risk]}">${u.avg_posture_score}/100</span>
      </div>
      <div class="posture-devices">
        ${u.devices.map(d => `
          <div class="posture-device">
            <div class="posture-device-name">💻 ${escapeHtml(d.device_name)}</div>
            <div class="posture-checks">
              ${postureCheck("OS Patched",    d.os_patched)}
              ${postureCheck("Antivirus",     d.antivirus_on)}
              ${postureCheck("Firewall",      d.firewall_on)}
              ${postureCheck("Disk Encrypted",d.disk_encrypted)}
            </div>
            <div class="posture-last-check">Last checked: ${formatRelativeTime(d.last_checked)}
              ${d.source === "simulated" ? '<em class="demo-label">(simulated)</em>' : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

function postureCheck(label, passing) {
  return `<span class="posture-check ${passing ? 'check-pass' : 'check-fail'}">
    ${passing ? '✅' : '❌'} ${label}
  </span>`;
}

/* ═══════════════════════════════════════════════════════════
   EMPLOYEE SELF-VIEW (own events + transparency panel)
═══════════════════════════════════════════════════════════ */

async function loadMyThreatEvents() {
  const container = document.getElementById("my-threat-events");
  if (!container) return;

  try {
    const res  = await apiGet("/api/threats/my-events");
    const data = await res.json();
    renderMyEvents(data);
  } catch {
    container.innerHTML = `<p class="text-muted">Could not load your events</p>`;
  }
}

function renderMyEvents(data) {
  const container = document.getElementById("my-threat-events");
  const scoreEl   = document.getElementById("my-risk-score");
  if (scoreEl) {
    scoreEl.textContent = `${data.risk_score}/100`;
    scoreEl.style.color = RISK_COLOR[data.risk_level] || "#94a3b8";
  }

  const collected = document.getElementById("what-we-collect");
  if (collected && data.what_we_collect) {
    collected.innerHTML = `<ul>${data.what_we_collect.map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ul>`;
  }

  if (!data.events || !data.events.length) {
    container.innerHTML = `<div class="empty-state"><p>No threat events attributed to your account</p></div>`;
    return;
  }

  container.innerHTML = data.events.map(ev => `
    <div class="threat-event-card severity-border-${ev.severity} ${ev.resolved ? 'event-resolved' : ''}">
      <div class="threat-event-header">
        <span class="badge ${SEV_CLASS[ev.severity] || 'badge-medium'}">${ev.severity.toUpperCase()}</span>
        <span class="mitre-tag">${MITRE_LABELS[ev.mitre_technique] || ev.mitre_technique}</span>
        <span class="threat-time">${formatRelativeTime(ev.created_at)}</span>
      </div>
      <div class="threat-type-label">${formatEventType(ev.event_type)}</div>
      <p class="threat-details">${escapeHtml(ev.details)}</p>
      ${ev.resolved ? '<span class="badge badge-resolved">RESOLVED</span>' : ''}
    </div>
  `).join('');
}

/* ═══════════════════════════════════════════════════════════
   FILTER CONTROLS
═══════════════════════════════════════════════════════════ */

function initThreatFilters() {
  const sevFilter  = document.getElementById("threat-filter-severity");
  const daysFilter = document.getElementById("threat-filter-days");
  const showResolved = document.getElementById("threat-show-resolved");

  if (sevFilter) {
    sevFilter.addEventListener("change", () => {
      _threatFilter.severity = sevFilter.value || null;
      loadThreatFeed();
    });
  }
  if (daysFilter) {
    daysFilter.addEventListener("change", () => {
      _threatFilter.days = parseInt(daysFilter.value) || 7;
      loadThreatFeed();
    });
  }
  if (showResolved) {
    showResolved.addEventListener("change", () => {
      _threatFilter.resolved = showResolved.checked;
      loadThreatFeed();
    });
  }
}

/* ═══════════════════════════════════════════════════════════
   PAGE INIT — called when #page-threats is shown
═══════════════════════════════════════════════════════════ */

async function initThreatDashboard() {
  initThreatFilters();
  await Promise.all([
    loadThreatFeed(),
    loadRiskScores(),
    loadFleetPosture(),
  ]);

  // Auto-refresh every 30s
  if (_threatPollTimer) clearInterval(_threatPollTimer);
  _threatPollTimer = setInterval(() => {
    loadThreatFeed();
    loadRiskScores();
    loadFleetPosture();
  }, 30000);
}

/* ═══════════════════════════════════════════════════════════
   UTILITY FUNCTIONS
═══════════════════════════════════════════════════════════ */

function formatEventType(type) {
  const map = {
    brute_force:            "🔑 Brute Force Login",
    after_hours_access:     "🌙 After-Hours Access",
    new_peer_ip:            "🌐 New Peer IP",
    failed_posture:         "🛡️ Failed Posture Check",
    large_download:         "📥 Large Download",
    malicious_dns:          "☠️ Malicious DNS Query",
    unusual_resource_access:"👁️ Unusual Resource Access",
    credential_tool:        "⚠️ Credential Dumping Tool",
  };
  return map[type] || type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatRelativeTime(iso) {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
            .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
