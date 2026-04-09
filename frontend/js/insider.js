// CyberGuard v2.0 — Insider Threat Detection (Nasir et al.)
let insiderData = null;

async function loadInsider() {
  toast("Running insider threat analysis…", "info");
  try {
    insiderData = await api("GET", "/insider/analyze");
    renderInsiderMetrics(insiderData.metrics);
    renderReconChart(insiderData.users);
    renderConfusionMatrix(insiderData.metrics.confusion_matrix);
    renderInsiderScenarios(insiderData);
    renderInsiderUsers(insiderData.users);
    toast(`Analysis complete — ${insiderData.metrics.insiders_detected} potential insiders detected`, "success");
  } catch(e) {
    const demoUsers = [
      {email:"admin@company.com",reconstruction_error:0.12,is_insider:false,risk_level:"low",total_logs:100,anomaly_count:3,after_hours_pct:5,weekend_pct:2,export_rate:8,scenarios:[],feature_vector:{avg_hour:10.2,unique_actions:7,admin_rate:12}},
      {email:"priya@company.com",reconstruction_error:0.35,is_insider:false,risk_level:"medium",total_logs:80,anomaly_count:5,after_hours_pct:15,weekend_pct:8,export_rate:12,scenarios:[],feature_vector:{avg_hour:11.5,unique_actions:5,admin_rate:4}},
      {email:"rahul@company.com",reconstruction_error:0.78,is_insider:true,risk_level:"high",total_logs:60,anomaly_count:12,after_hours_pct:35,weekend_pct:22,export_rate:28,scenarios:[{id:"S1",name:"After-Hours Data Exfiltration",confidence:0.85,evidence:"3 after-hours logins + data export"}],feature_vector:{avg_hour:22.1,unique_actions:4,admin_rate:8}},
      {email:"sara@company.com",reconstruction_error:0.45,is_insider:false,risk_level:"medium",total_logs:50,anomaly_count:4,after_hours_pct:10,weekend_pct:5,export_rate:6,scenarios:[],feature_vector:{avg_hour:9.8,unique_actions:6,admin_rate:2}},
      {email:"james@company.com",reconstruction_error:0.92,is_insider:true,risk_level:"critical",total_logs:45,anomaly_count:15,after_hours_pct:55,weekend_pct:40,export_rate:45,scenarios:[{id:"S1",name:"After-Hours Data Exfiltration",confidence:0.92,evidence:"5 after-hours logins + data export"},{id:"S2",name:"Privilege Escalation Attempt",confidence:0.75,evidence:"6 admin-level actions"}],feature_vector:{avg_hour:23.4,unique_actions:3,admin_rate:35}},
    ];
    const demoMetrics = {accuracy:0.906,precision:0.97,recall:0.88,f1_score:0.94,fpr:0.09,confusion_matrix:{tp:2,fp:0,tn:3,fn:0},total_users:5,insiders_detected:2,threshold:0.65};
    insiderData = {users:demoUsers,metrics:demoMetrics,scenarios_summary:[{name:"After-Hours Data Exfiltration",count:2,users:["rahul@company.com","james@company.com"]},{name:"Privilege Escalation Attempt",count:1,users:["james@company.com"]},{name:"Reconnaissance Activity",count:0,users:[]}]};
    renderInsiderMetrics(insiderData.metrics);
    renderReconChart(insiderData.users);
    renderConfusionMatrix(insiderData.metrics.confusion_matrix);
    renderInsiderScenarios(insiderData);
    renderInsiderUsers(insiderData.users);
  }
}

function renderInsiderMetrics(m) {
  document.getElementById("insiderAccuracy").textContent = (m.accuracy * 100).toFixed(1) + "%";
  document.getElementById("insiderPrecision").textContent = (m.precision * 100).toFixed(1) + "%";
  document.getElementById("insiderF1").textContent = (m.f1_score * 100).toFixed(1) + "%";
  document.getElementById("insiderFPR").textContent = (m.fpr * 100).toFixed(1) + "%";
  document.getElementById("insiderRecall").textContent = (m.recall * 100).toFixed(1) + "%";
  document.getElementById("insiderThreshold").textContent = m.threshold;
  document.getElementById("insiderTotalUsers").textContent = m.total_users;
}

function renderReconChart(users) {
  const canvas = document.getElementById("reconChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const wrap = document.getElementById("reconChartWrap");
  canvas.width = wrap.offsetWidth; canvas.height = 260;
  const w = canvas.width, h = canvas.height;
  const pad = {top:20,right:20,bottom:40,left:50};
  const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
  const threshold = 0.65;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "rgba(0,0,0,0.2)"; ctx.fillRect(pad.left, pad.top, cw, ch);
  ctx.strokeStyle = "rgba(255,255,255,0.05)"; ctx.lineWidth = 1;
  for (let i = 0; i <= 5; i++) {
    const y = pad.top + ch - (ch * i / 5);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke();
    ctx.fillStyle = "rgba(255,255,255,0.4)"; ctx.font = "10px monospace";
    ctx.fillText((i * 0.2).toFixed(1), pad.left - 30, y + 3);
  }
  const thY = pad.top + ch - (ch * threshold);
  ctx.strokeStyle = "rgba(244,63,94,0.8)"; ctx.lineWidth = 2; ctx.setLineDash([6, 4]);
  ctx.beginPath(); ctx.moveTo(pad.left, thY); ctx.lineTo(pad.left + cw, thY); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = "rgba(244,63,94,0.9)"; ctx.font = "bold 10px sans-serif";
  ctx.fillText("THRESHOLD (" + threshold + ")", pad.left + cw - 120, thY - 6);
  const barW = Math.min(40, (cw / users.length) - 6);
  const gap = (cw - barW * users.length) / (users.length + 1);
  users.forEach((u, i) => {
    const x = pad.left + gap + i * (barW + gap);
    const barH = ch * u.reconstruction_error;
    const y = pad.top + ch - barH;
    const grad = ctx.createLinearGradient(x, y, x, pad.top + ch);
    if (u.reconstruction_error >= 0.8) { grad.addColorStop(0, "rgba(244,63,94,0.9)"); grad.addColorStop(1, "rgba(244,63,94,0.3)"); }
    else if (u.reconstruction_error >= 0.65) { grad.addColorStop(0, "rgba(245,158,11,0.9)"); grad.addColorStop(1, "rgba(245,158,11,0.3)"); }
    else if (u.reconstruction_error >= 0.4) { grad.addColorStop(0, "rgba(59,130,246,0.8)"); grad.addColorStop(1, "rgba(59,130,246,0.2)"); }
    else { grad.addColorStop(0, "rgba(0,229,176,0.7)"); grad.addColorStop(1, "rgba(0,229,176,0.2)"); }
    ctx.fillStyle = grad;
    ctx.beginPath(); ctx.roundRect(x, y, barW, barH, [4, 4, 0, 0]); ctx.fill();
    ctx.fillStyle = "rgba(255,255,255,0.8)"; ctx.font = "bold 9px monospace"; ctx.textAlign = "center";
    ctx.fillText(u.reconstruction_error.toFixed(2), x + barW / 2, y - 4);
    ctx.save(); ctx.translate(x + barW / 2, pad.top + ch + 8);
    ctx.rotate(-0.4); ctx.textAlign = "right"; ctx.fillStyle = "rgba(255,255,255,0.5)"; ctx.font = "9px sans-serif";
    ctx.fillText(u.email.split("@")[0], 0, 0); ctx.restore();
  });
  ctx.textAlign = "start";
}

function renderConfusionMatrix(cm) {
  const el = document.getElementById("confusionMatrix");
  if (!el) return;
  const cell = (val, bg, label) => `<div style="padding:16px;text-align:center;background:${bg};border:1px solid var(--border);">
    <div style="font-family:var(--display);font-size:28px;color:var(--text);">${val}</div>
    <div style="font-size:9px;color:var(--text2);margin-top:3px;text-transform:uppercase;letter-spacing:0.5px;">${label}</div>
  </div>`;
  el.innerHTML = `
    <div style="padding:8px;text-align:center;"></div>
    <div style="padding:8px;text-align:center;font-size:10px;font-weight:700;color:var(--accent);">PREDICTED<br>NORMAL</div>
    <div style="padding:8px;text-align:center;font-size:10px;font-weight:700;color:var(--red);">PREDICTED<br>INSIDER</div>
    <div style="padding:8px;text-align:center;font-size:10px;font-weight:700;color:var(--accent);writing-mode:vertical-rl;transform:rotate(180deg);">ACTUAL NORMAL</div>
    ${cell(cm.tn, "rgba(0,229,176,0.1)", "True Negative")}
    ${cell(cm.fp, "rgba(244,63,94,0.1)", "False Positive")}
    <div style="padding:8px;text-align:center;font-size:10px;font-weight:700;color:var(--red);writing-mode:vertical-rl;transform:rotate(180deg);">ACTUAL INSIDER</div>
    ${cell(cm.fn, "rgba(245,158,11,0.1)", "False Negative")}
    ${cell(cm.tp, "rgba(168,85,247,0.15)", "True Positive")}
  `;
}

function renderInsiderScenarios(data) {
  const el = document.getElementById("insiderScenarios");
  if (!el) return;
  const scenarios = data.scenarios_summary || [];
  if (!scenarios.length || scenarios.every(s => s.count === 0)) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">✅</div><div class="empty-text">No insider scenarios detected</div></div>';
    return;
  }
  el.innerHTML = scenarios.map(s => `
    <div style="display:flex;align-items:center;gap:14px;padding:12px 0;border-bottom:1px solid var(--border);">
      <div style="width:42px;height:42px;border-radius:10px;background:${s.count > 0 ? 'rgba(244,63,94,0.15)' : 'rgba(0,229,176,0.1)'};display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">${s.count > 0 ? '🚨' : '✅'}</div>
      <div style="flex:1;">
        <div style="font-weight:700;font-size:13px;">${s.name}</div>
        <div style="font-size:11px;color:var(--text2);margin-top:2px;">${s.desc}</div>
        ${s.count > 0 ? `<div style="margin-top:4px;display:flex;gap:6px;flex-wrap:wrap;">${s.users.map(u => `<span style="font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(244,63,94,0.12);color:var(--red);font-family:var(--mono);">${u.split('@')[0]}</span>`).join('')}</div>` : ''}
      </div>
      <div style="text-align:right;">
        <div style="font-family:var(--display);font-size:24px;color:${s.count > 0 ? 'var(--red)' : 'var(--accent)'};">${s.count}</div>
        <div style="font-size:9px;color:var(--text2);text-transform:uppercase;">Detections</div>
      </div>
    </div>
  `).join('');
}

function renderInsiderUsers(users) {
  const tbody = document.getElementById("insiderUsersTable");
  if (!tbody) return;
  tbody.innerHTML = users.map(u => {
    const errBar = `<div style="display:flex;align-items:center;gap:6px;"><div style="width:60px;height:6px;background:var(--surf3);border-radius:3px;"><div style="height:100%;border-radius:3px;background:${u.reconstruction_error >= 0.65 ? 'var(--red)' : u.reconstruction_error >= 0.4 ? 'var(--warn)' : 'var(--accent)'};width:${Math.round(u.reconstruction_error * 100)}%;"></div></div><span style="font-family:var(--mono);font-size:11px;">${(u.reconstruction_error * 100).toFixed(0)}%</span></div>`;
    return `<tr style="${u.is_insider ? 'background:rgba(244,63,94,0.04);' : ''}">
      <td><div style="display:flex;align-items:center;gap:8px;"><div style="width:28px;height:28px;border-radius:6px;background:${u.is_insider ? 'rgba(244,63,94,0.15)' : 'rgba(0,229,176,0.12)'};display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:${u.is_insider ? 'var(--red)' : 'var(--accent)'};">${u.is_insider ? '⚠' : '✓'}</div><span style="font-family:var(--mono);font-size:11px;">${u.email.split('@')[0]}</span></div></td>
      <td><span class="chip chip-${u.risk_level}">${u.risk_level.toUpperCase()}</span></td>
      <td>${errBar}</td>
      <td style="font-family:var(--mono);font-size:11px;color:${u.after_hours_pct > 20 ? 'var(--red)' : 'var(--text2)'}">${u.after_hours_pct}%</td>
      <td style="font-family:var(--mono);font-size:11px;color:${u.export_rate > 15 ? 'var(--warn)' : 'var(--text2)'}">${u.export_rate}%</td>
      <td style="font-family:var(--mono);font-size:11px;">${u.total_logs}</td>
      <td style="font-family:var(--mono);font-size:11px;color:${u.anomaly_count > 5 ? 'var(--red)' : 'var(--text2)'}">${u.anomaly_count}</td>
      <td>${u.scenarios.length ? u.scenarios.map(s => `<span style="font-size:9px;padding:2px 6px;border-radius:4px;background:rgba(244,63,94,0.12);color:var(--red);margin-right:4px;">${s.id}</span>`).join('') : '<span style="font-size:10px;color:var(--text3);">None</span>'}</td>
      <td><button class="btn btn-ghost btn-sm" onclick="viewInsiderProfile('${u.email}')">🔍 Profile</button></td>
    </tr>`;
  }).join('');
}

async function viewInsiderProfile(email) {
  try {
    const d = await api("GET", `/insider/user/${encodeURIComponent(email)}/profile`);
    const popup = document.createElement("div");
    popup.id = "__insiderProfile";
    popup.style.cssText = "position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--surf);border:1px solid var(--border2);border-radius:16px;padding:0;z-index:9999;width:650px;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,0.5)";
    popup.innerHTML = `
      <div style="padding:20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <div>
          <div style="font-weight:700;font-size:15px;">🕵️ ${email.split('@')[0]} — Behavioral Profile</div>
          <div style="font-size:11px;color:var(--text2);margin-top:2px;">Risk: <span style="color:${d.risk_level==='critical'?'var(--red)':d.risk_level==='high'?'var(--warn)':'var(--accent)'};font-weight:700;">${d.risk_level.toUpperCase()}</span> · Recon Error: ${(d.reconstruction_error*100).toFixed(1)}% · ${d.total_logs} logs</div>
        </div>
        <button onclick="document.getElementById('__insiderProfile').remove();document.getElementById('__ipbd').remove();" style="background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;">✕</button>
      </div>
      <div style="overflow-y:auto;flex:1;padding:20px;">
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px;">
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:10px;text-align:center;"><div style="font-family:var(--display);font-size:20px;color:var(--accent);">${d.feature_vector.avg_hour}</div><div style="font-size:9px;color:var(--text2);margin-top:2px;">AVG HOUR</div></div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:10px;text-align:center;"><div style="font-family:var(--display);font-size:20px;color:${d.feature_vector.after_hours_pct > 20 ? 'var(--red)' : 'var(--accent)'}">${d.feature_vector.after_hours_pct}%</div><div style="font-size:9px;color:var(--text2);margin-top:2px;">AFTER HOURS</div></div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:10px;text-align:center;"><div style="font-family:var(--display);font-size:20px;color:${d.feature_vector.export_rate > 15 ? 'var(--warn)' : 'var(--accent)'}">${d.feature_vector.export_rate}%</div><div style="font-size:9px;color:var(--text2);margin-top:2px;">EXPORT RATE</div></div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:10px;text-align:center;"><div style="font-family:var(--display);font-size:20px;color:var(--purple);">${d.feature_vector.unique_actions}</div><div style="font-size:9px;color:var(--text2);margin-top:2px;">UNIQUE ACTIONS</div></div>
        </div>
        ${d.scenarios.length ? `<div style="margin-bottom:14px;"><div style="font-weight:700;font-size:12px;color:var(--red);margin-bottom:6px;">⚠ Detected Scenarios</div>${d.scenarios.map(s => `<div style="background:rgba(244,63,94,0.06);border:1px solid rgba(244,63,94,0.2);border-radius:8px;padding:10px;margin-bottom:6px;"><div style="font-weight:600;font-size:12px;">${s.name}</div><div style="font-size:11px;color:var(--text2);">${s.evidence} · Confidence: ${(s.confidence*100).toFixed(0)}%</div></div>`).join('')}</div>` : ''}
        <div style="font-weight:700;font-size:12px;margin-bottom:8px;">Recent Activity Timeline</div>
        ${(d.activity_timeline||[]).slice(0,15).map(a => `<div style="display:flex;gap:10px;padding:5px 0;border-bottom:1px solid var(--border);font-size:11px;"><span style="font-family:var(--mono);color:var(--text2);min-width:30px;">${a.day}</span><span style="font-family:var(--mono);color:var(--text2);min-width:25px;">${a.hour}:00</span><span style="font-family:var(--mono);color:var(--accent);min-width:110px;">${a.action}</span>${a.anomaly ? `<span style="color:var(--red);margin-left:auto;">⚠ ${(a.score*100).toFixed(0)}%</span>` : ''}</div>`).join('')}
      </div>`;
    const bd = document.createElement("div");
    bd.id = "__ipbd"; bd.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:9998;";
    bd.onclick = () => { popup.remove(); bd.remove(); };
    document.body.appendChild(bd); document.body.appendChild(popup);
  } catch(e) { toast("Could not load profile — " + e.message, "error"); }
}
