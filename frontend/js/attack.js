// CyberGuard v2.0 — Attack Simulation & ML Classifier
async function simulateAttack(type) {
  const labels = { brute_force:"Brute Force Login", data_exfiltration:"Data Exfiltration", insider_threat:"Insider Threat", credential_stuffing:"Credential Stuffing" };
  const attacks = {
    brute_force: { title:"Brute Force Login Attack Detected", severity:"critical", category:"Network", description:"150+ failed login attempts from IP 185.220.101.45 at 2:00 AM. Possible credential cracking tool detected by ML Anomaly Engine.", logs:[ {action:"login",ip:"185.220.101.45",hour:"02:03 AM",anomalyScore:0.97}, {action:"login",ip:"185.220.101.46",hour:"02:11 AM",anomalyScore:0.95}, {action:"login",ip:"185.220.101.78",hour:"02:19 AM",anomalyScore:0.96} ] },
    data_exfiltration: { title:"Suspicious Bulk Data Export at 3AM", severity:"critical", category:"Data Leak", description:"45 report export actions in 1 hour at 3:00 AM from single user. ML confidence: 95%. Possible insider data theft.", logs:[ {action:"export_report",ip:"192.168.1.22",hour:"03:12 AM",anomalyScore:0.94}, {action:"export_report",ip:"192.168.1.22",hour:"03:28 AM",anomalyScore:0.95}, {action:"export_report",ip:"192.168.1.22",hour:"03:41 AM",anomalyScore:0.93} ] },
    insider_threat: { title:"Insider Threat — Mass Deletion at 10PM", severity:"critical", category:"Insider Threat", description:"Bulk vendor record deletion at 10:45 PM from internal IP. Outside normal hours. ML flagged as high-confidence insider threat.", logs:[ {action:"delete_vendor",ip:"192.168.1.10",hour:"10:45 PM",anomalyScore:0.91}, {action:"delete_vendor",ip:"192.168.1.10",hour:"10:47 PM",anomalyScore:0.92}, {action:"delete_alert",ip:"192.168.1.10",hour:"10:52 PM",anomalyScore:0.90} ] },
    credential_stuffing: { title:"Credential Stuffing from 23 IPs", severity:"critical", category:"Network", description:"Login attempts from 23 different IPs in 10 minutes at 1:00 AM. Automated tool detected. ML anomaly score: 97%.", logs:[ {action:"login",ip:"91.108.4.12",hour:"01:04 AM",anomalyScore:0.97}, {action:"login",ip:"178.62.11.3",hour:"01:05 AM",anomalyScore:0.96}, {action:"login",ip:"104.21.88.9",hour:"01:06 AM",anomalyScore:0.97} ] }
  };
  if (!confirm(`Simulate a ${labels[type]} attack?\n\nThis will:\n• Add 3 suspicious anomaly log entries\n• Create a critical ML alert\n• Update the dashboard`)) return;
  const atk = attacks[type];
  try { const d = await api("POST", "/logs/simulate-attack", { type }); await updateBadges(); await loadDashboard(); toast(`✅ ${labels[type]} simulated! Check Alerts & ML Anomalies tabs.`, "success"); return; } catch(e) {}
  const newAlert = { id: Date.now(), title: atk.title, severity: atk.severity, category: atk.category, status:"open", description: atk.description, source:"ml", mlScore:0.95, createdAt: new Date().toISOString() };
  DEMO_DATA.alerts.unshift(newAlert);
  DEMO_DATA.dashboard.openAlerts += 1; DEMO_DATA.dashboard.criticalAlerts += 1; DEMO_DATA.dashboard.anomaliesDetected += 3;
  const now = new Date();
  atk.logs.forEach((l, i) => { DEMO_DATA.logs.unshift({ id: Date.now() + i, userEmail:"admin@company.com", action: l.action, ipAddress: l.ip, timestamp: new Date(now - i * 600000).toISOString(), isAnomaly: true, anomalyScore: l.anomalyScore }); });
  await loadDashboard(); await updateBadges();
  const popup = document.createElement("div");
  popup.style.cssText = "position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--surf);border:1px solid rgba(244,63,94,0.4);border-radius:16px;padding:28px;z-index:9999;min-width:420px;max-width:520px;box-shadow:0 20px 60px rgba(0,0,0,0.5)";
  popup.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
      <div style="width:40px;height:40px;border-radius:10px;background:rgba(244,63,94,0.15);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;">🚨</div>
      <div><div style="font-size:15px;font-weight:700;color:var(--red);">Attack Simulated!</div><div style="font-size:12px;color:var(--text2);">${labels[type]}</div></div>
      <button onclick="this.closest('div[style]').remove()" style="margin-left:auto;background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;">✕</button>
    </div>
    <div style="background:rgba(244,63,94,0.06);border:1px solid rgba(244,63,94,0.2);border-radius:8px;padding:12px;margin-bottom:14px;font-size:12px;color:var(--text2);">${atk.description}</div>
    <div style="font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;">ML Anomaly Logs Created</div>
    ${atk.logs.map(l=>`<div style="display:flex;justify-content:space-between;padding:6px 10px;background:var(--surf2);border-radius:6px;margin-bottom:4px;font-size:11px;font-family:var(--mono);">
      <span style="color:var(--warn);">${l.action}</span><span style="color:var(--text2);">${l.ip}</span><span style="color:var(--text2);">${l.hour}</span><span style="color:var(--red);">score: ${l.anomalyScore}</span>
    </div>`).join("")}
    <div style="display:flex;gap:8px;margin-top:16px;">
      <button onclick="this.closest('div[style]').remove();goPage('alerts',document.querySelector('.nav-item[onclick*=alerts]'))" class="btn btn-danger btn-sm" style="flex:1">View Alert →</button>
      <button onclick="this.closest('div[style]').remove();goPage('anomalies',document.querySelector('.nav-item[onclick*=anomalies]'))" class="btn btn-primary btn-sm" style="flex:1">ML Anomalies →</button>
    </div>`;
  document.body.appendChild(popup);
  const bd = document.createElement("div");
  bd.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:9998;";
  bd.onclick = () => { popup.remove(); bd.remove(); };
  document.body.appendChild(bd);
}

// Attack Surface
let attackFilterLevel = "";
const ATTACK_DATA = [
  ["admin.acmecorp.com","critical","RDP & SSH exposed","22, 3389","CVE-2023-32019","Restrict to VPN only"],
  ["api.acmecorp.com","critical","SSL cert expiring","443","—","Renew SSL certificate"],
  ["dev.acmecorp.com","high","Port 8443 exposed","8443","CVE-2023-44487","Block or add WAF"],
  ["mail.acmecorp.com","high","TLS 1.0 supported","25, 465","—","Disable TLS < 1.2"],
  ["acmecorp.com","medium","Missing CSP header","443","—","Add Content-Security-Policy"],
  ["acmecorp.com","medium","No CAA DNS record","—","—","Add CAA record"],
  ["static.acmecorp.com","low","HTTP redirect missing","80","—","Force HTTPS redirect"],
];
function renderAttack(filterRisk) {
  const tbody = document.getElementById("attackTable");
  if (!tbody) return;
  const data = filterRisk ? ATTACK_DATA.filter(([_,r]) => r === filterRisk) : ATTACK_DATA;
  tbody.innerHTML = data.map(([asset,risk,issue,port,cve,rem]) => `<tr>
    <td><span style="font-family:var(--mono);font-size:12px;">${asset}</span></td>
    <td><span class="chip chip-${risk}" style="cursor:pointer;" onclick="event.stopPropagation();filterAttackSurface('${risk}')">${risk.charAt(0).toUpperCase()+risk.slice(1)}</span></td>
    <td style="font-size:12px;">${issue}</td>
    <td><span style="font-family:var(--mono);font-size:11px;color:var(--text2);">${port}</span></td>
    <td><span style="font-family:var(--mono);font-size:11px;color:${cve!=="—"?"var(--warn)":"var(--text3)"};">${cve}</span></td>
    <td style="font-size:12px;color:var(--text2);">${rem}</td>
  </tr>`).join("");
  if (filterRisk && data.length > 0) toast(`Showing ${data.length} ${filterRisk} risk items`, "info");
  if (filterRisk && data.length === 0) toast(`No ${filterRisk} risk items found`, "warn");
}
function filterAttackSurface(level) {
  if (attackFilterLevel === level) { attackFilterLevel = ""; renderAttack(); toast("Filter cleared — showing all", "info"); }
  else { attackFilterLevel = level; renderAttack(level); }
}
function exportAttack() {
  const rows = [["Asset","Risk","Issue","Port","CVE","Remediation"],["admin.acmecorp.com","critical","RDP exposed","22,3389","CVE-2023-32019","Restrict to VPN"]];
  downloadCSV(rows, "attack-surface.csv");
}

// ML Classifier
function classifyThreat() { document.getElementById("classifyText").value = ""; document.getElementById("classifyResult").style.display = "none"; openModal("classifyModal"); }
async function runClassify() {
  const text = document.getElementById("classifyText").value.trim();
  if (!text) { toast("Enter text", "warn"); return; }
  try {
    const d = await api("POST", "/logs/ml/classify", { text });
    const colors = { benign:"var(--accent)", suspicious:"var(--warn)", phishing:"var(--red)", malware:"var(--red)" };
    const el = document.getElementById("classifyResult");
    el.style.display = "block";
    el.innerHTML = `<div style="background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.2);border-radius:8px;padding:14px;">
      <div style="font-size:18px;font-weight:700;color:${colors[d.label]||'var(--text)'};margin-bottom:8px;">${d.label.toUpperCase()} <span style="font-size:12px;color:var(--text2);">(${(d.confidence*100).toFixed(1)}% confident)</span></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">${Object.entries(d.probabilities||{}).map(([k,v])=>`<span style="font-size:11px;padding:2px 8px;border-radius:4px;background:var(--surf3);font-family:var(--mono);">${k}: ${(v*100).toFixed(1)}%</span>`).join("")}</div>
    </div>`;
  } catch(e) {
    const t = text.toLowerCase();
    let label, confidence;
    if (/ransomware|malware|trojan|keylogger|rootkit|virus|exploit/.test(t))       { label="malware";    confidence=0.94; }
    else if (/phish|click here|verify account|suspend|urgent|reset password/.test(t)) { label="phishing";   confidence=0.91; }
    else if (/unusual|failed login|3am|bulk export|tor|unknown ip/.test(t))        { label="suspicious";  confidence=0.83; }
    else                                                                             { label="benign";     confidence=0.88; }
    const probs = {benign:0.05,suspicious:0.05,phishing:0.05,malware:0.05};
    probs[label] = confidence;
    const colors = { benign:"var(--accent)", suspicious:"var(--warn)", phishing:"var(--red)", malware:"var(--red)" };
    const el = document.getElementById("classifyResult");
    el.style.display = "block";
    el.innerHTML = `<div style="background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.2);border-radius:8px;padding:14px;">
      <div style="font-size:18px;font-weight:700;color:${colors[label]};margin-bottom:8px;">${label.toUpperCase()} <span style="font-size:12px;color:var(--text2);">(${(confidence*100).toFixed(1)}% confident)</span></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">${Object.entries(probs).map(([k,v])=>`<span style="font-size:11px;padding:2px 8px;border-radius:4px;background:var(--surf3);font-family:var(--mono);">${k}: ${(v*100).toFixed(1)}%</span>`).join("")}</div>
      <div style="margin-top:8px;font-size:11px;color:var(--text2);">⚠ Demo mode — connect backend for real ML classification</div>
    </div>`;
  }
}
