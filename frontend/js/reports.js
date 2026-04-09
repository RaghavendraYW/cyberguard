// CyberGuard v2.0 — Reports
async function loadReports() {
  try {
    const d = await api("GET", "/reports/");
    const el = document.getElementById("reportList");
    el.innerHTML = d.reports?.length ? `<table><thead><tr><th>Title</th><th>Type</th><th>Generated</th><th>Pages</th><th>Actions</th></tr></thead><tbody>${d.reports.map(r=>`<tr>
      <td style="font-weight:600;">${r.title}</td>
      <td><span class="chip chip-info">${r.type}</span></td>
      <td style="font-size:12px;color:var(--text2);">${r.date}</td>
      <td style="font-family:var(--mono);font-size:12px;">${r.pages}</td>
      <td><div style="display:flex;gap:6px;">
        <button class="btn btn-ghost btn-sm" onclick="downloadReport(${r.id})">⬇ Download</button>
        <button class="btn btn-danger btn-sm" onclick="deleteReport(${r.id})">🗑</button>
      </div></td>
    </tr>`).join("")}</tbody></table>` :
    '<div class="empty-state"><div class="empty-icon">📄</div><div class="empty-text">No reports yet</div></div>';
  } catch (e) {}
}
function openGenReportModal() { openModal("reportGenModal"); }
async function generateReport() {
  const type = document.getElementById("reportType").value;
  try {
    const d = await api("POST", "/reports/generate", { type });
    closeModal("reportGenModal"); await loadReports();
    toast("Report generated!", "success");
    const blob = new Blob([d.content || ""], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = type + "-report.txt"; a.click();
    URL.revokeObjectURL(url);
  } catch (e) { toast("Report generation failed", "error"); }
}
async function downloadReport(id) {
  try {
    const d = await api("GET", `/reports/${id}/download`);
    const blob = new Blob([d.content || ""], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = (d.title || "report") + ".txt"; a.click();
    URL.revokeObjectURL(url);
    toast("Downloaded!", "success");
  } catch (e) { toast("Download failed", "error"); }
}
async function deleteReport(id) {
  if (!confirm("Delete?")) return;
  await api("DELETE", `/reports/${id}`); await loadReports(); toast("Deleted", "success");
}
