// CyberGuard v2.5 — Helper Functions
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function timeAgo(iso) {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "Just now";
  if (diff < 3600) return Math.floor(diff/60) + "m ago";
  if (diff < 86400) return Math.floor(diff/3600) + "h ago";
  return Math.floor(diff/86400) + "d ago";
}
function formatTimestamp(iso) {
  if (!iso) return "—";
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: true, timeZoneName: "short"
    }).format(new Date(iso));
  } catch(e) { return new Date(iso).toLocaleString(); }
}
function downloadCSV(rows, filename) {
  const content = rows.map(r => r.map(c => `"${(c||"").toString().replace(/"/g,'""')}"`).join(",")).join("\n");
  const blob = new Blob([content], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
  toast(filename + " downloaded", "success");
}
function openModal(id) { document.getElementById(id).style.display = "flex"; document.body.style.overflow = "hidden"; }
function closeModal(id) { document.getElementById(id).style.display = "none"; document.body.style.overflow = ""; }
function closeBg(e, id) { if (e.target === document.getElementById(id)) closeModal(id); }
function toast(msg, type = "info") {
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span>${{success:"✓",error:"✕",info:"ℹ",warn:"⚠"}[type]||"ℹ"}</span><span>${msg}</span>`;
  document.getElementById("toastContainer").appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// ── SVG Empty States ──────────────────────────────────────────
function renderEmptyState(type = "general", title = "No data found", subtitle = "") {
  const svgs = {
    vendors: `<svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent);opacity:0.85;">
      <path d="M3 21h18M5 21V7l8-4v18M19 21V11l-6-4M9 9h1M9 13h1M9 17h1M14 13h1M14 17h1"/>
    </svg>`,
    alerts: `<svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent);opacity:0.85;">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    reports: `<svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent);opacity:0.85;">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
      <polyline points="10 9 9 9 8 9"/>
    </svg>`,
    leaks: `<svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent);opacity:0.85;">
      <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      <circle cx="12" cy="16" r="1"/>
    </svg>`,
    anomalies: `<svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--purple);opacity:0.85;">
      <circle cx="12" cy="12" r="10"/>
      <path d="m4.93 4.93 4.24 4.24"/>
      <path d="m14.83 9.17 4.24-4.24"/>
      <path d="m14.83 14.83 4.24 4.24"/>
      <path d="m9.17 14.83-4.24 4.24"/>
      <circle cx="12" cy="12" r="2"/>
    </svg>`,
    general: `<svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text3);opacity:0.75;">
      <circle cx="12" cy="12" r="10"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`
  };

  const svg = svgs[type] || svgs.general;
  return `
    <div class="empty-state-card" style="padding:48px 24px;text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:auto;">
      <div class="empty-state-illustration" style="margin-bottom:14px;background:rgba(255,255,255,0.02);padding:16px;border-radius:50%;border:1px dashed var(--border);">${svg}</div>
      <div style="font-size:14px;font-weight:700;color:var(--text);margin-bottom:6px;">${title}</div>
      ${subtitle ? `<div style="font-size:12px;color:var(--text2);max-width:320px;line-height:1.5;">${subtitle}</div>` : ""}
    </div>
  `;
}
