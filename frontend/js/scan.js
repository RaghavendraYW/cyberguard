// CyberGuard v2.0 — Scan
async function bsFullScan() {
  const domain = document.getElementById("bsDomainInput").value.trim();
  if (!domain) { toast("Enter a domain", "warn"); return; }
  const el = document.getElementById("bsScanResult");
  el.innerHTML = '<div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2);"><span class="spinner"></span> Running real security checks on ' + domain + '…</div>';
  try {
    const d = await api("POST", "/scan/domain", { domain });
    const gradeColor = g => ({A:"var(--accent)",B:"var(--accent)",C:"var(--warn)",D:"var(--red)",F:"var(--red)"}[g] || "var(--text2)");
    el.innerHTML = `<div style="background:var(--surf2);border-radius:8px;padding:16px;border:1px solid var(--border);">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
        <div><div style="font-weight:700;font-family:var(--mono);">${d.domain}</div><div style="font-size:11px;color:var(--text2);">Real scan results</div></div>
        <span style="font-family:var(--display);font-size:26px;color:${d.score>=700?'var(--accent)':d.score>=500?'var(--warn)':'var(--red)'};">${d.score}/950</span>
      </div>
      <div class="scan-grid">${Object.entries(d.grades).map(([k,g])=>`<div class="scan-metric"><span class="scan-grade" style="color:${gradeColor(g)};">${g}</span><div class="scan-lbl">${k.toUpperCase()}</div></div>`).join("")}</div>
      ${(d.findings||[]).length ? `<div style="margin-top:12px;"><div style="font-size:11px;font-weight:700;color:var(--text2);margin-bottom:6px;">FINDINGS</div>${(d.findings||[]).slice(0,8).map(f=>`<div style="font-size:12px;color:var(--warn);margin-bottom:3px;">⚠ ${f}</div>`).join("")}</div>` : ""}
      ${(d.alertsCreated||[]).length ? `<div style="margin-top:10px;font-size:12px;color:var(--red);">🔔 ${(d.alertsCreated||[]).length} alert(s) auto-created: ${d.alertsCreated.join(", ")}</div>` : ""}
    </div>`;
    if ((d.alertsCreated||[]).length) await updateBadges();
    toast(`Scan complete — Score: ${d.score}`, "success");
  } catch (e) { el.innerHTML = `<div style="color:var(--red);font-size:12px;">Scan failed: ${e.message}</div>`; }
}

function openScanModal() {
  document.getElementById("scanProgress").style.display = "none";
  document.getElementById("scanDone").style.display = "none";
  document.getElementById("scanModalFooter").style.display = "flex";
  document.getElementById("scan-domain").value = "";
  document.getElementById("scanBar").style.width = "0";
  document.getElementById("scanLog").innerHTML = "";
  openModal("scanModal");
}
async function startScan() {
  const domain = document.getElementById("scan-domain").value.trim() || "example.com";
  document.getElementById("scanModalFooter").style.display = "none";
  document.getElementById("scanProgress").style.display = "block";
  const logEl = document.getElementById("scanLog");
  const barEl = document.getElementById("scanBar");
  const logs = ["Resolving DNS records…","Checking SSL/TLS certificate…","Analyzing HTTP security headers…","Testing email security (SPF/DKIM/DMARC)…","Scanning for exposed ports…","Running ML risk assessment…","Generating security report…"];
  for (let i = 0; i < logs.length; i++) {
    document.getElementById("scanStatusText").textContent = logs[i];
    logEl.innerHTML += `<div style="color:var(--accent);">▶ ${logs[i]}</div>`;
    logEl.scrollTop = logEl.scrollHeight;
    barEl.style.width = ((i+1)/logs.length*80) + "%";
    await new Promise(r => setTimeout(r, 400));
  }
  try {
    const d = await api("POST", "/scan/domain", { domain });
    barEl.style.width = "100%";
    document.getElementById("scanProgress").style.display = "none";
    const done = document.getElementById("scanDone");
    done.style.display = "block";
    done.innerHTML = `<div style="text-align:center;padding:8px 0;">
      <div style="font-size:32px;margin-bottom:8px;">✅</div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;"><span style="font-weight:700;font-family:var(--mono);">${d.domain}</span><div style="text-align:right;"><span style="font-family:var(--display);font-size:24px;color:${d.score>=700?'var(--accent)':d.score>=500?'var(--warn)':'var(--red)'};">${d.score}/950</span><div style="font-size:10px;color:var(--text2);">Grade: ${d.score>=900?'A+':d.score>=850?'A':d.score>=800?'A-':d.score>=750?'B+':d.score>=700?'B':d.score>=650?'B-':d.score>=600?'C+':d.score>=550?'C':d.score>=450?'D':'F'}</div></div></div>
      <div style="font-size:12px;color:var(--text2);margin-bottom:14px;">${(d.findings||[]).length} findings</div>
      ${(d.findings||[]).slice(0,5).map(f=>`<div style="font-size:12px;color:var(--warn);text-align:left;margin-bottom:3px;">⚠ ${f}</div>`).join("")}
      <div style="display:flex;gap:8px;justify-content:center;margin-top:14px;">
        <button class="btn btn-primary btn-sm" onclick="closeModal('scanModal');goPage('attack',document.querySelector('[data-page=attack]'))">View Details</button>
        <button class="btn btn-ghost btn-sm" onclick="closeModal('scanModal')">Close</button>
      </div>
    </div>`;
    if ((d.alertsCreated||[]).length) { await updateBadges(); toast(`${(d.alertsCreated||[]).length} alerts auto-created`, "warn"); }
  } catch (e) {
    document.getElementById("scanDone").style.display = "block";
    document.getElementById("scanDone").innerHTML = `<div style="text-align:center;color:var(--red);">Scan failed: ${e.message}</div>`;
  }
}
async function quickScan() {
  const domain = document.getElementById("quickDomain").value.trim() || "example.com";
  document.getElementById("scanningBadge").style.display = "flex";
  document.getElementById("quickScanResult").style.display = "none";
  try {
    const d = await api("POST", "/scan/domain", { domain });
    document.getElementById("scanningBadge").style.display = "none";
    const el = document.getElementById("quickScanResult");
    el.style.display = "block";
    const gradeColor = g => ({A:"var(--accent)",B:"var(--accent)",C:"var(--warn)",D:"var(--red)",F:"var(--red)"}[g]||"var(--text2)");
    el.innerHTML = `<div style="background:var(--surf2);border-radius:8px;padding:14px;border:1px solid var(--border);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;"><span style="font-weight:700;font-family:var(--mono);">${d.domain}</span><div style="text-align:right;"><span style="font-family:var(--display);font-size:24px;color:${d.score>=700?'var(--accent)':d.score>=500?'var(--warn)':'var(--red)'};">${d.score}/950</span><div style="font-size:10px;color:var(--text2);">Grade: ${d.score>=900?'A+':d.score>=850?'A':d.score>=800?'A-':d.score>=750?'B+':d.score>=700?'B':d.score>=650?'B-':d.score>=600?'C+':d.score>=550?'C':d.score>=450?'D':'F'}</div></div></div>
      <div class="scan-grid">${Object.entries(d.grades).map(([k,g])=>`<div class="scan-metric"><span class="scan-grade" style="color:${gradeColor(g)};">${g}</span><div class="scan-lbl">${k.toUpperCase()}</div></div>`).join("")}</div>
      ${(d.findings||[]).slice(0,4).map(f=>`<div style="font-size:11px;color:var(--warn);margin-top:4px;">⚠ ${f}</div>`).join("")}
    </div>`;
    if ((d.alertsCreated||[]).length) await updateBadges();
  } catch (e) {
    document.getElementById("scanningBadge").style.display = "none";
    document.getElementById("quickScanResult").style.display = "block";
    document.getElementById("quickScanResult").innerHTML = `<div style="color:var(--red);font-size:12px;">Scan failed — ${e.message}</div>`;
  }
}
