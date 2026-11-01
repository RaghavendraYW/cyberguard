// CyberGuard v2.0 — Reports (Enterprise)
// Supports type filter, date-range filter, preview modal, PDF download, delete.

// ── Load & render report list ─────────────────────────────────
async function loadReports() {
  const el = document.getElementById("reportList");
  if (!el) return;

  // Read filter values
  const typeFilter  = document.getElementById("reportTypeFilter")?.value || "";
  const dateFrom    = document.getElementById("reportDateFrom")?.value || "";
  const dateTo      = document.getElementById("reportDateTo")?.value || "";

  // Build query string
  let qs = "?";
  if (typeFilter) qs += `type=${encodeURIComponent(typeFilter)}&`;
  if (dateFrom)   qs += `from=${encodeURIComponent(dateFrom)}&`;
  if (dateTo)     qs += `to=${encodeURIComponent(dateTo)}&`;

  el.innerHTML = '<div style="padding:24px;text-align:center;"><div class="spinner"></div></div>';

  try {
    const d = await api("GET", "/reports/" + qs);
    let reports = d.reports || [];

    // Client-side filter by date if backend doesn't support it
    if (dateFrom) reports = reports.filter(r => r.date >= dateFrom);
    if (dateTo)   reports = reports.filter(r => r.date <= dateTo);
    if (typeFilter) reports = reports.filter(r => r.type === typeFilter);

    if (!reports.length) {
      el.innerHTML = '<div class="empty-state"><div class="empty-icon">📄</div><div class="empty-text">No reports match your filters</div></div>';
      return;
    }

    el.innerHTML = `<div class="tbl-wrap"><table>
      <thead><tr>
        <th>Title</th><th>Type</th><th>Generated</th><th>Pages</th><th>Actions</th>
      </tr></thead>
      <tbody>${reports.map(r => `<tr>
        <td style="font-weight:600;">${_escHtml(r.title)}</td>
        <td><span class="chip chip-info" style="text-transform:capitalize;">${(r.type||"").replace(/-/g," ")}</span></td>
        <td style="font-size:12px;color:var(--text2);">${r.date || "—"}</td>
        <td style="font-family:var(--mono);font-size:12px;">${r.pages}</td>
        <td><div style="display:flex;gap:6px;">
          <button class="btn btn-ghost btn-sm" onclick="previewReport(${r.id})" title="Preview in modal">👁 Preview</button>
          <button class="btn btn-ghost btn-sm" onclick="downloadReport(${r.id},'pdf')" title="Download PDF">📄 PDF</button>
          <button class="btn btn-ghost btn-sm" onclick="downloadReport(${r.id},'txt')" title="Download text">⬇ Text</button>
          <button class="btn btn-danger btn-sm" onclick="deleteReport(${r.id})" title="Delete report">🗑</button>
        </div></td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  } catch (e) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">📄</div><div class="empty-text">No reports yet. Generate your first report above.</div></div>';
  }
}

function _escHtml(s) {
  const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML;
}

// ── Generate ──────────────────────────────────────────────────
function openGenReportModal() { openModal("reportGenModal"); }

async function generateReport() {
  const type = document.getElementById("reportType").value;
  const btn  = document.querySelector("#reportGenModal .btn-primary");
  if (btn) { btn.disabled = true; btn.textContent = "Generating…"; }
  try {
    const d = await api("POST", "/reports/generate", { type });
    closeModal("reportGenModal");
    toast("✅ Report generated!", "success");
    await loadReports();
    if (d.id) {
      previewReport(d.id);
    }
  } catch (e) {
    toast("Report generation failed: " + (e.message || "Unknown error"), "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Generate"; }
  }
}

// ── Preview Modal ─────────────────────────────────────────────
async function previewReport(id) {
  let overlay = document.getElementById("reportPreviewOverlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "reportPreviewOverlay";
    overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9000;display:flex;align-items:center;justify-content:center;padding:24px;";
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    document.body.appendChild(overlay);
  }

  overlay.innerHTML = `<div style="background:var(--surf);border-radius:16px;width:100%;max-width:760px;max-height:85vh;display:flex;flex-direction:column;border:1px solid var(--border);box-shadow:0 20px 60px rgba(0,0,0,0.5);">
    <div style="padding:18px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
      <div style="font-weight:700;font-size:15px;display:flex;align-items:center;gap:8px;">
        <span>📄</span> <span id="reportPreviewTitle">Report Preview</span>
      </div>
      <button onclick="document.getElementById('reportPreviewOverlay').remove()" style="background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;">✕</button>
    </div>
    <div id="reportPreviewBody" style="padding:20px 24px;overflow-y:auto;flex:1;font-size:13px;line-height:1.7;color:var(--text2);">
      <div style="text-align:center;padding:40px;"><div class="spinner"></div></div>
    </div>
    <div style="padding:14px 24px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end;align-items:center;">
      <button class="btn btn-ghost" onclick="document.getElementById('reportPreviewOverlay').remove()">Close</button>
      <button class="btn btn-ghost" onclick="downloadReport(${id}, 'pdf');document.getElementById('reportPreviewOverlay').remove()">📄 Download PDF</button>
      <button class="btn btn-primary" onclick="downloadReport(${id}, 'txt');document.getElementById('reportPreviewOverlay').remove()">⬇ Download Text</button>
    </div>
  </div>`;

  try {
    const d = await api("GET", `/reports/${id}`);
    const titleEl = document.getElementById("reportPreviewTitle");
    if (titleEl && d.title) titleEl.textContent = d.title;
    const content = d.content || "No content available.";
    const body = document.getElementById("reportPreviewBody");
    if (body) {
      body.innerHTML = `
        <div style="background:var(--surf2);border-radius:8px;padding:20px;border:1px solid var(--border);">
          <div style="font-family:var(--mono);font-size:11px;white-space:pre-wrap;color:var(--text);line-height:1.6;">${_escHtml(content)}</div>
        </div>`;
    }
  } catch (e) {
    const body = document.getElementById("reportPreviewBody");
    if (body) body.innerHTML = '<div style="text-align:center;color:var(--text3);padding:30px;">Could not load report content: ' + (e.message || "Error") + '</div>';
  }
}

// ── Download ──────────────────────────────────────────────────
async function downloadReport(id, format = "txt") {
  try {
    const url = `${API_BASE}/reports/${id}/${format === "pdf" ? "pdf" : "download"}`;
    const res = await fetch(url, {
      headers: {
        ...(TOKEN ? { "Authorization": "Bearer " + TOKEN } : {}),
        "X-Requested-With": "XMLHttpRequest"
      }
    });
    if (!res.ok) throw new Error("Download returned status " + res.status);
    const blob = await res.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = `cyberguard_report_${id}.${format === "pdf" ? "pdf" : "txt"}`;
    a.click();
    URL.revokeObjectURL(blobUrl);
    toast(`⬇ Report downloaded (${format.toUpperCase()})`, "success");
  } catch (e) {
    toast("Download failed: " + e.message, "error");
  }
}

// ── Delete ────────────────────────────────────────────────────
async function deleteReport(id) {
  if (!confirm("Delete this report? This cannot be undone.")) return;
  try {
    await api("DELETE", `/reports/${id}`);
    toast("Report deleted", "success");
    await loadReports();
  } catch (e) {
    toast("Delete failed: " + e.message, "error");
  }
}
