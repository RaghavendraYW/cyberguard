// CyberGuard v2.0 — Alerts
async function loadAlerts() {
  const sevF  = document.getElementById("alertSevFilter")?.value || "";
  const statF = document.getElementById("alertStatusFilter")?.value || "";
  try {
    const params = new URLSearchParams({ severity: sevF, status: statF });
    const d = await api("GET", `/alerts/?${params}`);
    const el = document.getElementById("alertsList");
    if (!el) return;
    el.innerHTML = d.alerts?.length ? d.alerts.map(a => alertHTML(a)).join("") :
      '<div class="empty-state"><div class="empty-icon">🎉</div><div class="empty-text">No alerts</div></div>';
  } catch (e) {
    const el = document.getElementById("alertsList");
    if (el) el.innerHTML = DEMO_DATA.alerts.map(a=>alertHTML(a)).join("");
  }
}
function renderAlerts() { loadAlerts(); }
function alertHTML(a, compact = false) {
  const dotColor = {critical:"var(--red)",high:"var(--warn)",medium:"var(--blue)",low:"var(--accent)"}[a.severity] || "var(--text2)";
  const statusChip = a.status === "resolved" ? '<span class="chip chip-ok">Resolved</span>' : a.status === "acknowledged" ? '<span class="chip chip-info">Acked</span>' : '<span class="chip chip-critical">Open</span>';
  const mlBadge = a.source === "ml" ? `<span class="ml-badge">🤖 ML ${(a.mlScore*100).toFixed(0)}%</span>` : "";
  return `<div class="alert-item" onclick="viewAlert(${a.id})">
    <div class="alert-dot" style="background:${dotColor};${a.severity==='critical'?'box-shadow:0 0 6px '+dotColor:''}"></div>
    <div style="flex:1;">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px;">
        <div class="alert-title">${a.title}</div>${mlBadge}
      </div>
      <div class="alert-meta">${a.category}${!compact?' · '+a.status:''}</div>
    </div>
    ${!compact ? statusChip : ""}
    <div class="alert-time">${timeAgo(a.createdAt)}</div>
  </div>`;
}
async function viewAlert(id) {
  try {
    const a = await api("GET", `/alerts/${id}`);
    const ml = a.mlClassification || {};
    openModal("alertModal");
    document.getElementById("al-title").value = a.title;
    document.getElementById("al-sev").value = a.severity;
    document.getElementById("al-desc").value = a.description;
    if (ml.label) {
      const mlDiv = document.getElementById("mlClassResult");
      mlDiv.style.display = "block";
      mlDiv.innerHTML = `🤖 ML Classification: <strong style="color:var(--purple);">${ml.label.toUpperCase()}</strong> (${(ml.confidence*100).toFixed(1)}% confidence)`;
    }
  } catch (e) {}
}
function openAlertModal() {
  ["al-title","al-desc"].forEach(id => document.getElementById(id).value = "");
  document.getElementById("mlClassResult").style.display = "none";
  openModal("alertModal");
}
async function mlClassifyAlert() {
  const text = document.getElementById("al-title").value + " " + document.getElementById("al-desc").value;
  if (!text.trim()) { toast("Enter some text first", "warn"); return; }
  try {
    const d = await api("POST", "/logs/ml/classify", { text });
    const mlDiv = document.getElementById("mlClassResult");
    mlDiv.style.display = "block";
    mlDiv.innerHTML = `🤖 ML Classification: <strong style="color:var(--purple);">${d.label.toUpperCase()}</strong> (${(d.confidence*100).toFixed(1)}% confidence)<br><span style="font-size:10px;color:var(--text3);">Probabilities: ${Object.entries(d.probabilities||{}).map(([k,v])=>`${k}:${(v*100).toFixed(0)}%`).join(' | ')}</span>`;
    if (d.label === "malware" || d.label === "phishing") document.getElementById("al-sev").value = d.label === "malware" ? "critical" : "high";
    toast(`Classified as: ${d.label}`, "info");
  } catch (e) { toast("ML classify failed — is backend running?", "error"); }
}
async function saveAlert() {
  const title = document.getElementById("al-title").value.trim();
  if (!title) { toast("Title required", "error"); return; }
  try {
    await api("POST", "/alerts/", { title, severity: document.getElementById("al-sev").value, category: document.getElementById("al-cat").value, description: document.getElementById("al-desc").value });
    closeModal("alertModal"); await loadAlerts(); await updateBadges();
    toast("Alert created (ML classified automatically)", "success");
  } catch (e) { toast(e.message, "error"); }
}
async function bulkAcknowledge() {
  await api("POST", "/alerts/bulk-acknowledge"); await loadAlerts(); await updateBadges(); toast("All alerts acknowledged", "success");
}
