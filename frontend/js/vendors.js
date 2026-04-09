// CyberGuard v2.0 — Vendors
let allVendors = [];
async function loadVendors() {
  try {
    const search = document.getElementById("vendorSearch")?.value || "";
    const risk   = document.getElementById("vendorRiskFilter")?.value || "";
    const params = new URLSearchParams({ search, risk });
    const d = await api("GET", `/vendors/?${params}`);
    allVendors = d.vendors || [];
    document.getElementById("vendorCount").textContent = `${allVendors.length} vendors monitored`;
    renderVendors();
  } catch(e) {
    allVendors = DEMO_DATA.vendors;
    document.getElementById("vendorCount").textContent = `${allVendors.length} vendors monitored`;
    renderVendors();
  }
}
function renderVendors() {
  const tbody = document.getElementById("vendorTableBody");
  if (!tbody) return;
  const search = (document.getElementById("vendorSearch")?.value || "").toLowerCase();
  const riskF  = document.getElementById("vendorRiskFilter")?.value || "";
  let vendors  = allVendors.filter(v => {
    if (search && !v.name.toLowerCase().includes(search) && !v.domain.includes(search)) return false;
    if (riskF && v.mlRisk !== riskF) return false;
    return true;
  });
  tbody.innerHTML = vendors.length ? vendors.map(v => {
    const sc = v.score;
    const ruleRisk = v.risk;
    const mlRisk   = v.mlRisk || ruleRisk;
    const scoreColor = sc >= 800 ? "var(--accent)" : sc >= 650 ? "var(--warn)" : "var(--red)";
    return `<tr>
      <td><div style="display:flex;align-items:center;gap:10px;"><div style="width:32px;height:32px;border-radius:7px;border:1px solid var(--border);background:var(--surf2);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;font-family:var(--mono);">${v.name.substring(0,2).toUpperCase()}</div><div><div style="font-weight:600;">${v.name}</div><div style="font-size:11px;color:var(--text2);">${v.domain}</div></div></div></td>
      <td><span style="font-family:var(--mono);font-size:12px;font-weight:700;padding:3px 8px;border-radius:6px;background:${scoreColor}18;color:${scoreColor};">${sc}</span></td>
      <td><span class="chip chip-${ruleRisk}">${ruleRisk}</span></td>
      <td><span class="chip chip-${mlRisk}" style="background:rgba(168,85,247,0.1);color:#a855f7;border:1px solid rgba(168,85,247,0.2);">🤖 ${mlRisk}</span></td>
      <td style="font-size:12px;color:var(--text2);">${v.category}</td>
      <td style="font-family:var(--mono);font-size:12px;">${v.issues}</td>
      <td><span class="chip chip-${v.status==='monitored'?'ok':'high'}">${v.status}</span></td>
      <td style="font-size:12px;color:var(--text2);">${v.lastScanned}</td>
      <td><div style="display:flex;gap:6px;">
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();scanVendor(${v.id})">⚡</button>
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();openVendorModal(${v.id})">✏️</button>
        <button class="btn btn-danger btn-sm" onclick="event.stopPropagation();deleteVendor(${v.id})">🗑</button>
      </div></td>
    </tr>`;
  }).join("") :
    `<tr><td colspan="9"><div class="empty-state"><div class="empty-icon">🏢</div><div class="empty-text">No vendors found</div></div></td></tr>`;
}
function openVendorModal(id) {
  const v = id ? allVendors.find(x => x.id === id) : null;
  document.getElementById("vendorModalTitle").textContent = v ? "Edit Vendor" : "Add Vendor";
  document.getElementById("vendorEditId").value = id || "";
  document.getElementById("v-name").value = v?.name || "";
  document.getElementById("v-domain").value = v?.domain || "";
  document.getElementById("v-contact").value = v?.contact || "";
  document.getElementById("v-notes").value = v?.notes || "";
  openModal("vendorModal");
}
async function saveVendor() {
  const id = document.getElementById("vendorEditId").value;
  const body = { name: document.getElementById("v-name").value.trim(), domain: document.getElementById("v-domain").value.trim(), category: document.getElementById("v-cat").value, criticality: document.getElementById("v-crit").value, contact: document.getElementById("v-contact").value, notes: document.getElementById("v-notes").value };
  if (!body.name || !body.domain) { toast("Name and domain required", "error"); return; }
  try {
    if (id) await api("PUT", `/vendors/${id}`, body);
    else await api("POST", "/vendors/", body);
    closeModal("vendorModal"); await loadVendors(); await updateBadges();
    toast(id ? "Vendor updated" : "Vendor added — ML risk scored", "success");
    trackAction("add_vendor");
  } catch (e) { toast(e.message, "error"); }
}
async function deleteVendor(id) {
  if (!confirm("Remove vendor?")) return;
  await api("DELETE", `/vendors/${id}`); await loadVendors(); toast("Vendor removed", "success");
}
async function scanVendor(id) {
  toast("Scanning vendor…", "info");
  try {
    const d = await api("POST", `/vendors/${id}/scan`);
    await loadVendors(); await updateBadges();
    toast(d.message || "Scan complete", "success");
  } catch (e) { toast("Scan failed", "error"); }
}
function exportVendors() {
  const rows = [["Name","Domain","Score","Risk","ML Risk","Category","Issues","Status"]];
  allVendors.forEach(v => rows.push([v.name,v.domain,v.score,v.risk,v.mlRisk||v.risk,v.category,v.issues,v.status]));
  downloadCSV(rows, "vendors.csv");
}
async function rescanAllVendors() {
  if (!allVendors.length) { toast("No vendors to scan", "warn"); return; }
  if (!confirm(`Rescan all ${allVendors.length} vendors? This may take a moment.`)) return;
  toast(`Rescanning ${allVendors.length} vendors…`, "info");
  try {
    const d = await api("POST", "/vendors/rescan-all");
    await loadVendors(); await updateBadges();
    toast(`✅ Rescanned ${d.rescanned || allVendors.length} vendors`, "success");
  } catch(e) {
    toast("Rescan failed", "error");
  }
}
