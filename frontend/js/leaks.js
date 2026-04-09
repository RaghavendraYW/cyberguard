// CyberGuard v2.0 — Leaks
async function loadLeaks() {
  try {
    const d = await api("GET", "/leaks/");
    document.getElementById("activeLeaks").textContent = d.active || 0;
    document.getElementById("credExposed").textContent = d.credentials || 0;
    document.getElementById("underInv").textContent = d.investigating || 0;
    const el = document.getElementById("leaksList");
    el.innerHTML = d.leaks?.length ? d.leaks.map(l => {
      const dotColor = {critical:"var(--red)",high:"var(--warn)",medium:"var(--blue)",low:"var(--accent)"}[l.severity];
      return `<div class="alert-item" style="${l.severity==='critical'?'border-color:rgba(244,63,94,0.3)':''}">
        <div class="alert-dot" style="background:${dotColor};"></div>
        <div style="flex:1;"><div style="display:flex;gap:8px;margin-bottom:4px;"><div class="alert-title">${l.title}</div><span class="chip chip-${l.severity}">${l.severity}</span><span class="chip chip-${l.status==='resolved'?'ok':l.status==='investigating'?'high':'critical'}">${l.status}</span></div>
        <div class="alert-meta">${l.source}${l.credentials>0?' · '+l.credentials+' creds':''}${l.records>0?' · '+l.records+' records':''}</div>
        <div style="font-size:12px;color:var(--text2);margin-top:3px;">${l.details}</div></div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
          <div class="alert-time">${timeAgo(l.createdAt)}</div>
          ${l.status!=='resolved'?`<button class="btn btn-blue btn-sm" onclick="updateLeak(${l.id},'investigating')">🔍</button>`:''}
          <button class="btn btn-ghost btn-sm" onclick="updateLeak(${l.id},'resolved')">✓</button>
          <button class="btn btn-danger btn-sm" onclick="deleteLeak(${l.id})">🗑</button>
        </div>
      </div>`;
    }).join("") : '<div class="empty-state"><div class="empty-icon">✅</div><div class="empty-text">No leaks detected</div></div>';
  } catch (e) {
    document.getElementById("activeLeaks").textContent = DEMO_DATA.leaks.filter(l=>l.status!=="resolved").length;
    document.getElementById("credExposed").textContent = DEMO_DATA.leaks.reduce((s,l)=>s+l.credentials,0);
    document.getElementById("underInv").textContent = DEMO_DATA.leaks.filter(l=>l.status==="investigating").length;
    const el = document.getElementById("leaksList");
    if (el) {
      el.innerHTML = DEMO_DATA.leaks.map(l => {
        const dotColor = {critical:"var(--red)",high:"var(--warn)",medium:"var(--blue)",low:"var(--accent)"}[l.severity];
        return `<div class="alert-item"><div class="alert-dot" style="background:${dotColor};"></div>
          <div style="flex:1;"><div style="display:flex;gap:8px;margin-bottom:4px;"><div class="alert-title">${l.title}</div>
          <span class="chip chip-${l.severity}">${l.severity}</span><span class="chip chip-high">${l.status}</span></div>
          <div class="alert-meta">${l.source}${l.credentials>0?" · "+l.credentials+" creds":""}</div>
          <div style="font-size:12px;color:var(--text2);margin-top:3px;">${l.details}</div></div></div>`;
      }).join("");
    }
  }
}
function openLeakModal() { ["lk-title","lk-details"].forEach(id=>document.getElementById(id).value=""); openModal("leakModal"); }
async function saveLeak() {
  const title = document.getElementById("lk-title").value.trim();
  if (!title) { toast("Title required", "error"); return; }
  await api("POST", "/leaks/", { title, severity: document.getElementById("lk-sev").value, source: document.getElementById("lk-src").value, credentials: parseInt(document.getElementById("lk-creds").value)||0, records: parseInt(document.getElementById("lk-recs").value)||0, details: document.getElementById("lk-details").value });
  closeModal("leakModal"); await loadLeaks(); await updateBadges(); toast("Leak added", "success");
}
async function updateLeak(id, status) {
  await api("PUT", `/leaks/${id}`, { status }); await loadLeaks(); await updateBadges(); toast(`Leak marked as ${status}`, "success");
}
async function deleteLeak(id) {
  if (!confirm("Delete?")) return;
  await api("DELETE", `/leaks/${id}`); await loadLeaks(); toast("Deleted", "success");
}
async function refreshLeaks() { toast("Refreshing data leaks…","info"); await loadLeaks(); toast("Data leaks refreshed ✓","success"); }
