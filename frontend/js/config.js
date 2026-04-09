// CyberGuard v2.0 — Config & API
const API_BASE = (() => {
  if (location.hostname === "localhost" || location.hostname === "127.0.0.1") return `http://${location.hostname}:8000/api`;
  return "/api";
})();
let TOKEN = "", CURRENT_USER = null;

async function api(method, path, body = null) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (TOKEN) opts.headers["Authorization"] = "Bearer " + TOKEN;
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(API_BASE + path, opts);
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || r.statusText); }
  return r.json();
}

function requiresBackend(op) {
  if (TOKEN === "demo-token-cyberguard") { toast(`${op} requires a running backend. Start the server first.`, "warn"); return true; }
  return false;
}

async function trackAction(action, meta = {}) {
  try { await api("POST", "/logs/track", { action, page: document.querySelector(".nav-item.active")?.dataset?.page || "", userAgent: navigator.userAgent, meta }); } catch (e) {}
}
