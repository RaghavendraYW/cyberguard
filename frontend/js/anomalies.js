// CyberGuard v2.0 — Anomalies
async function loadAnomalies() {
  try {
    const d = await api("GET", "/logs/?anomalies=true&limit=100");
    const logs = d.logs || [];
    document.getElementById("totalAnomalies").textContent = d.anomalyCount || 0;
    document.getElementById("highConfAnomalies").textContent = logs.filter(l => l.anomalyScore > 0.7).length;
    const mlAlerts = await api("GET", "/alerts/?severity=high");
    document.getElementById("mlAlerts").textContent = (mlAlerts.alerts || []).filter(a => a.source === "ml").length;
    const tbody = document.getElementById("anomaliesTable");
    tbody.innerHTML = logs.length ? logs.map(l => `<tr>
      <td style="font-family:var(--mono);font-size:11px;">${l.userEmail}</td>
      <td><span class="chip chip-high">${l.action}</span></td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text2);">${l.ipAddress}</td>
      <td><div style="display:flex;align-items:center;gap:8px;"><div style="height:4px;width:60px;background:var(--surf3);border-radius:2px;"><div style="height:100%;border-radius:2px;background:${l.anomalyScore>0.7?'var(--red)':'var(--warn)'};width:${Math.round(l.anomalyScore*100)}%;"></div></div><span style="font-family:var(--mono);font-size:11px;">${(l.anomalyScore*100).toFixed(0)}%</span></div></td>
      <td style="font-size:11px;color:var(--text2);" title="${formatTimestamp(l.timestamp)}">${timeAgo(l.timestamp)}<div style="font-size:9px;color:var(--text3);">${formatTimestamp(l.timestamp)}</div></td>
    </tr>`).join("") : `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">✅</div><div class="empty-text">No anomalies detected</div></div></td></tr>`;
  } catch(e) {
    const logs = DEMO_DATA.logs.filter(l=>l.isAnomaly);
    document.getElementById("totalAnomalies").textContent = logs.length;
    document.getElementById("highConfAnomalies").textContent = logs.filter(l=>l.anomalyScore>0.7).length;
    document.getElementById("mlAlerts").textContent = 2;
    const tbody = document.getElementById("anomaliesTable");
    if (tbody) tbody.innerHTML = logs.map(l=>`<tr>
      <td style="font-family:var(--mono);font-size:11px;">${l.userEmail}</td>
      <td><span class="chip chip-high">${l.action}</span></td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text2);">${l.ipAddress}</td>
      <td><div style="display:flex;align-items:center;gap:8px;"><div style="height:4px;width:60px;background:var(--surf3);border-radius:2px;"><div style="height:100%;border-radius:2px;background:${l.anomalyScore>0.7?"var(--red)":"var(--warn)"};width:${Math.round(l.anomalyScore*100)}%;"></div></div><span style="font-family:var(--mono);font-size:11px;">${(l.anomalyScore*100).toFixed(0)}%</span></div></td>
      <td style="font-size:11px;color:var(--text2);" title="${formatTimestamp(l.timestamp)}">${timeAgo(l.timestamp)}<div style="font-size:9px;color:var(--text3);">${formatTimestamp(l.timestamp)}</div></td>
    </tr>`).join("");
  }
}
async function retrainModel() {
  toast("Retraining ML model…", "info");
  try {
    const d = await api("POST", "/logs/ml/retrain");
    if (d.status === "retrained") {
      const accuracy = d.accuracy ? `${(d.accuracy * 100).toFixed(1)}%` : "N/A";
      const anomalyRate = d.anomaly_rate ? `${(d.anomaly_rate * 100).toFixed(1)}%` : "N/A";
      toast(`✅ Model retrained on ${d.samples || 0} samples — Accuracy: ${accuracy}`, "success");
      const popup = document.createElement("div");
      popup.style.cssText = "position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--surf);border:1px solid rgba(168,85,247,0.3);border-radius:16px;padding:28px;z-index:9999;width:420px;box-shadow:0 20px 60px rgba(0,0,0,0.5);text-align:center;";
      popup.innerHTML = `
        <div style="font-size:28px;margin-bottom:8px;">🤖</div>
        <div style="font-weight:700;font-size:16px;margin-bottom:6px;color:var(--purple);">Model Retrained Successfully</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:16px 0;">
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:12px;">
            <div style="font-family:var(--display);font-size:28px;color:var(--accent);">${d.samples || 0}</div>
            <div style="font-size:10px;color:var(--text2);margin-top:2px;">TRAINING SAMPLES</div>
          </div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:12px;">
            <div style="font-family:var(--display);font-size:28px;color:var(--purple);">${accuracy}</div>
            <div style="font-size:10px;color:var(--text2);margin-top:2px;">MODEL ACCURACY</div>
          </div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:12px;">
            <div style="font-family:var(--display);font-size:28px;color:var(--warn);">${anomalyRate}</div>
            <div style="font-size:10px;color:var(--text2);margin-top:2px;">ANOMALY RATE</div>
          </div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:12px;">
            <div style="font-family:var(--display);font-size:28px;color:var(--blue);">${d.rescored || 0}</div>
            <div style="font-size:10px;color:var(--text2);margin-top:2px;">LOGS RE-SCORED</div>
          </div>
        </div>
        <button onclick="this.closest('div[style]').remove();document.getElementById('__rtbd')?.remove()" class="btn btn-primary" style="width:100%">Got it</button>`;
      const bd = document.createElement("div");
      bd.id = "__rtbd"; bd.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:9998;";
      bd.onclick = () => { popup.remove(); bd.remove(); };
      document.body.appendChild(bd); document.body.appendChild(popup);
      await loadAnomalies();
    } else if (d.status === "insufficient_data") {
      toast(`Not enough data to retrain (${d.count} logs, need 50+)`, "warn");
    } else {
      toast(`Retrain status: ${d.status}`, "warn");
    }
  } catch (e) { toast("Retrain failed — is backend running?", "error"); }
}
async function refreshAnomalies() { toast("Refreshing anomalies…","info"); await loadAnomalies(); toast("Anomalies refreshed ✓","success"); }
