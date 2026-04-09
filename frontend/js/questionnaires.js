// CyberGuard v2.0 — Questionnaires
let qStatusFilter = "";
async function loadQuestionnaires() {
  const vSel = document.getElementById("q-vendor");
  if (vSel) { vSel.innerHTML = '<option value="">Internal</option>' + allVendors.map(v=>`<option value="${v.name}">${v.name}</option>`).join(""); }
  try {
    const params = qStatusFilter ? `?status=${qStatusFilter}` : "";
    const d = await api("GET", `/questionnaires/${params}`);
    const el = document.getElementById("qList");
    el.innerHTML = d.questionnaires?.length ? d.questionnaires.map(q => {
      const pct = q.percent;
      const statusColor = {completed:"var(--accent)",in_progress:"var(--blue)",pending:"var(--warn)"}[q.status] || "var(--text2)";
      return `<div class="q-card">
        <div style="width:38px;height:38px;border-radius:8px;background:var(--surf3);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">📋</div>
        <div style="flex:1;"><div style="font-size:13px;font-weight:600;margin-bottom:2px;">${q.title}</div><div style="font-size:11px;color:var(--text2);">${q.framework} · ${q.vendor||'Internal'} · Due ${q.due||'—'}</div></div>
        <div style="min-width:90px;text-align:right;"><div style="font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent);margin-bottom:4px;">${pct}%</div><div class="prog-wrap"><div class="prog-fill" style="width:${pct}%;background:${statusColor};"></div></div><div style="font-size:10px;color:${statusColor};margin-top:3px;">${q.status.replace('_',' ')}</div></div>
        <div style="display:flex;gap:6px;margin-left:12px;">
          <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();updateQProgress(${q.id},${q.answered},${q.total})">📝</button>
          <button class="btn btn-danger btn-sm" onclick="event.stopPropagation();deleteQ(${q.id})">🗑</button>
        </div>
      </div>`;
    }).join("") : '<div class="empty-state"><div class="empty-icon">📋</div><div class="empty-text">No questionnaires</div></div>';
  } catch (e) {}
}
function filterQ(status, el) {
  qStatusFilter = status;
  document.querySelectorAll("#page-questionnaires .tab").forEach(t => t.classList.remove("active"));
  if (el) el.classList.add("active");
  loadQuestionnaires();
}
function openQModal(id) {
  document.getElementById("qModalTitle").textContent = id ? "Edit Questionnaire" : "New Questionnaire";
  document.getElementById("qEditId").value = id || "";
  document.getElementById("q-title").value = "";
  openModal("qModal");
}
async function saveQ() {
  const title = document.getElementById("q-title").value.trim();
  if (!title) { toast("Title required", "error"); return; }
  const id = document.getElementById("qEditId").value;
  const body = { title, framework: document.getElementById("q-fw").value, vendor: document.getElementById("q-vendor").value, due: document.getElementById("q-due").value, total: parseInt(document.getElementById("q-total").value) || 20 };
  try {
    if (id) await api("PUT", `/questionnaires/${id}`, body);
    else await api("POST", "/questionnaires/", body);
    closeModal("qModal"); await loadQuestionnaires(); await updateBadges(); await renderCompliance();
    toast("Saved — compliance scores updated", "success");
  } catch (e) { toast(e.message, "error"); }
}
async function updateQProgress(id, current, total) {
  const ans = prompt(`Answered questions (0-${total}):`, current);
  if (ans === null) return;
  const n = parseInt(ans);
  if (isNaN(n) || n < 0 || n > total) { toast("Invalid number", "error"); return; }
  await api("PUT", `/questionnaires/${id}`, { answered: n });
  await loadQuestionnaires(); await renderCompliance(); toast("Progress updated — compliance scores recalculated", "success");
}
async function deleteQ(id) {
  if (!confirm("Delete?")) return;
  await api("DELETE", `/questionnaires/${id}`); await loadQuestionnaires(); toast("Deleted", "success");
}
