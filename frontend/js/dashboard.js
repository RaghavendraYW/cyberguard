// CyberGuard v2.0 — Dashboard
let scoreTrendChart = null, riskDonutChart = null;

const DEMO_DATA = {
  dashboard: {score:742,grade:"B+",openAlerts:4,criticalAlerts:3,vendorCount:6,activeLeaks:2,anomaliesDetected:11,industryPct:73,
    scoreTrend:[710,720,715,730,738,740,742],
    riskDist:{critical:3,high:1,medium:2,low:0},
    mlStatus:{anomalyDetector:{status:"active",model:"Isolation Forest"},vendorRiskScorer:{status:"active",model:"Random Forest"},threatClassifier:{status:"active",model:"Naive Bayes"}}},
  vendors:[
    {id:1,name:"Salesforce",domain:"salesforce.com",category:"CRM",criticality:"Critical",score:880,issues:2,status:"monitored",trend:"+5",risk:"low",mlRisk:"low"},
    {id:2,name:"AWS",domain:"aws.amazon.com",category:"Cloud Infrastructure",criticality:"Critical",score:912,issues:1,status:"monitored",trend:"+2",risk:"low",mlRisk:"low"},
    {id:3,name:"CloudHostPro",domain:"cloudhostpro.io",category:"Cloud Infrastructure",criticality:"High",score:540,issues:18,status:"review",trend:"-42",risk:"high",mlRisk:"critical"},
    {id:4,name:"Slack",domain:"slack.com",category:"Communication",criticality:"High",score:820,issues:5,status:"monitored",trend:"-8",risk:"low",mlRisk:"medium"},
    {id:5,name:"Stripe",domain:"stripe.com",category:"Payment Processing",criticality:"Critical",score:930,issues:1,status:"monitored",trend:"+7",risk:"low",mlRisk:"low"},
    {id:6,name:"Zoom",domain:"zoom.us",category:"Communication",criticality:"Medium",score:690,issues:11,status:"review",trend:"-15",risk:"medium",mlRisk:"high"}
  ],
  alerts:[
    {id:1,title:"SSL Certificate expiring in 7 days",severity:"critical",category:"Website Security",status:"open",description:"api.acmecorp.com SSL cert expires soon.",createdAt:new Date().toISOString()},
    {id:2,title:"Admin panel exposed to public internet",severity:"critical",category:"Network",status:"open",description:"admin.acmecorp.com is publicly accessible.",createdAt:new Date().toISOString()},
    {id:3,title:"Vendor score dropped 42 points",severity:"high",category:"Vendor Risk",status:"open",description:"CloudHostPro dropped.",createdAt:new Date().toISOString()},
    {id:4,title:"DMARC policy not enforced",severity:"high",category:"Email Security",status:"acknowledged",description:"DMARC in p=none mode.",createdAt:new Date().toISOString()},
    {id:5,title:"New credential leak detected",severity:"critical",category:"Data Leak",status:"open",description:"2 credentials found in dark web.",createdAt:new Date().toISOString()}
  ],
  leaks:[
    {id:1,title:"Corporate credentials on BreachForums",severity:"critical",source:"Dark Web",credentials:2,records:0,status:"investigating",details:"Credentials found in breach dump.",createdAt:new Date().toISOString()},
    {id:2,title:"API keys on Pastebin",severity:"high",source:"Paste Site",credentials:0,records:0,status:"open",details:"API keys found publicly.",createdAt:new Date().toISOString()}
  ],
  questionnaires:[
    {id:1,title:"SOC 2 Assessment",framework:"SOC 2",vendor:"CloudHostPro",total:21,answered:15,status:"in_progress",due:"2026-04-20",percent:71},
    {id:2,title:"GDPR Compliance Review",framework:"GDPR",vendor:"",total:11,answered:11,status:"completed",due:"2026-02-28",percent:100}
  ],
  logs: Array.from({length:20},(_,i)=>({id:i+1,userEmail:"admin@company.com",action:["login","view_dashboard","export_report","scan_domain"][i%4],ipAddress:"192.168.1.10",timestamp:new Date(Date.now()-i*3600000).toISOString(),isAnomaly:i<3,anomalyScore:i<3?0.92:0.1}))
};

async function updateBadges() {
  try {
    const [alerts, leaks, logs] = await Promise.all([
      api("GET", "/alerts/?status=open"),
      api("GET", "/leaks/"),
      api("GET", "/logs/?limit=1")
    ]);
    const setB = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setB("badge-alerts", alerts.open || 0);
    setB("alertDot", alerts.open || 0);
    setB("badge-leaks", leaks.active || 0);
    setB("badge-anomalies", logs.anomalyCount || 0);
    const vendors = await api("GET", "/vendors/stats");
    setB("badge-vendors", vendors.riskDistribution?.critical || 0);
  } catch (e) {
    const el = document.getElementById("qList");
    if (el) el.innerHTML = DEMO_DATA.questionnaires.map(q => {
      const pct = q.percent;
      const statusColor = {completed:"var(--accent)",in_progress:"var(--blue)",pending:"var(--warn)"}[q.status]||"var(--text2)";
      return `<div class="q-card">
        <div style="width:38px;height:38px;border-radius:8px;background:var(--surf3);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">📋</div>
        <div style="flex:1;"><div style="font-size:13px;font-weight:600;margin-bottom:2px;">${q.title}</div><div style="font-size:11px;color:var(--text2);">${q.framework} · ${q.vendor||"Internal"} · Due ${q.due||"—"}</div></div>
        <div style="min-width:90px;text-align:right;"><div style="font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent);margin-bottom:4px;">${pct}%</div><div class="prog-wrap"><div class="prog-fill" style="width:${pct}%;background:${statusColor};"></div></div><div style="font-size:10px;color:${statusColor};margin-top:3px;">${q.status.replace("_"," ")}</div></div>
      </div>`;
    }).join("");
  }
}

async function loadDashboard() {
  try {
    const d = await api("GET", "/dashboard/summary");
    document.getElementById("dashScore").textContent = d.score;
    document.getElementById("dashGrade").textContent = d.grade;
    document.getElementById("dashRisks").textContent = d.openAlerts;
    document.getElementById("dashVendors").textContent = d.vendorCount;
    document.getElementById("dashAnomalies").textContent = d.anomaliesDetected;
    document.getElementById("industryPct").textContent = d.industryPct + "%";
    document.getElementById("ringVal").textContent = d.score;
    document.getElementById("ringGrade").textContent = "Grade: " + d.grade;
    animateRing(d.score, 950);
    renderScoreTrend(d.scoreTrend || []);
    renderRiskDonut(d.riskDist || {});
    renderMLStatus(d.mlStatus || {});
    await loadDashAlerts();
  } catch (e) {
    const d = DEMO_DATA.dashboard;
    document.getElementById("dashScore").textContent = d.score;
    document.getElementById("dashGrade").textContent = d.grade;
    document.getElementById("dashRisks").textContent = d.openAlerts;
    document.getElementById("dashVendors").textContent = d.vendorCount;
    document.getElementById("dashAnomalies").textContent = d.anomaliesDetected;
    document.getElementById("industryPct").textContent = d.industryPct + "%";
    document.getElementById("ringVal").textContent = d.score;
    document.getElementById("ringGrade").textContent = "Grade: " + d.grade;
    animateRing(d.score, 950);
    renderScoreTrend(d.scoreTrend);
    renderRiskDonut(d.riskDist);
    renderMLStatus(d.mlStatus);
    loadDashAlerts();
  }
}

function animateRing(val, max) {
  const circ = 345.4;
  const arc  = document.getElementById("ringArc");
  const offset = circ - (val / max) * circ;
  arc.style.transition = "stroke-dashoffset 1.5s cubic-bezier(0.4,0,0.2,1)";
  setTimeout(() => { arc.style.strokeDashoffset = offset; }, 100);
}

function renderScoreTrend(trend) {
  const ctx = document.getElementById("scoreTrendChart");
  if (!ctx) return;
  if (scoreTrendChart) scoreTrendChart.destroy();
  const labels = ["Day 1","Day 2","Day 3","Day 4","Day 5","Day 6","Today"].slice(-trend.length);
  scoreTrendChart = new Chart(ctx, {
    type: "line",
    data: { labels, datasets: [{ data: trend, borderColor: "#00e5b0", backgroundColor: "rgba(0,229,176,0.08)", fill: true, tension: 0.4, pointRadius: 3 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#8896b3", font: { size: 10 } } }, y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#8896b3", font: { size: 10 } } } } }
  });
}

function renderRiskDonut(dist) {
  const ctx = document.getElementById("riskDonutChart");
  if (!ctx) return;
  if (riskDonutChart) riskDonutChart.destroy();
  const { critical=0, high=0, medium=0, low=0 } = dist;
  riskDonutChart = new Chart(ctx, {
    type: "doughnut",
    data: { labels: ["Critical","High","Medium","Low"], datasets: [{ data: [critical,high,medium,low], backgroundColor: ["#f43f5e","#f59e0b","#3b82f6","#00e5b0"], borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "72%", plugins: { legend: { display: false } } }
  });
  document.getElementById("riskLegend").innerHTML =
    [["Critical",critical,"var(--red)"],["High",high,"var(--warn)"],["Medium",medium,"var(--blue)"],["Low",low,"var(--accent)"]].map(([l,v,c]) =>
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><span style="width:10px;height:10px;border-radius:50%;background:${c};flex-shrink:0;"></span><span style="font-size:12px;color:var(--text2);">${l}</span><span style="margin-left:auto;font-family:var(--mono);font-size:12px;font-weight:700;">${v}</span></div>`
    ).join("");
}

function renderMLStatus(ml) {
  const el = document.getElementById("mlStatusGrid");
  if (!el) return;
  el.innerHTML = Object.entries(ml).map(([k, v]) => `
    <div style="background:var(--surf2);border:1px solid var(--border);border-radius:8px;padding:14px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="width:8px;height:8px;border-radius:50%;background:${v.status==='active'?'var(--accent)':'var(--red)'};animation:${v.status==='active'?'pulse 1.5s infinite':'none'};flex-shrink:0;"></span>
        <span style="font-size:12px;font-weight:700;">${v.model}</span>
      </div>
      <div style="font-size:11px;color:var(--text2);">${v.description}</div>
      <div style="font-size:10px;color:${v.status==='active'?'var(--accent)':'var(--red)'};margin-top:4px;font-family:var(--mono);">${v.status.toUpperCase()}</div>
    </div>`).join("");
}

async function loadDashAlerts() {
  const el = document.getElementById("dashAlertsList");
  if (!el) return;
  try {
    const d = await api("GET", "/alerts/");
    const alerts = (d.alerts || []).filter(a => a.status !== "resolved").slice(0, 5);
    el.innerHTML = alerts.length ? alerts.map(a => alertHTML(a, true)).join("") :
      '<div class="empty-state"><div class="empty-icon">✅</div><div class="empty-text">No open alerts</div></div>';
  } catch (e) {
    if (el) el.innerHTML = DEMO_DATA.alerts.slice(0,5).map(a=>alertHTML(a,true)).join("");
  }
}
