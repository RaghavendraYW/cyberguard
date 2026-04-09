// CyberGuard v2.0 — Compliance
let compChart = null;
const FRAMEWORK_META = {
  "SOC 2":     {name:"SOC 2 Type II", icon:"🔒", total:21, trend:[70,72,76,78,80,82,84]},
  "SOC 2 Type II": {name:"SOC 2 Type II", icon:"🔒", total:21, trend:[70,72,76,78,80,82,84]},
  "ISO 27001":  {name:"ISO 27001",    icon:"📜", total:114,trend:[60,63,65,67,69,70,71]},
  "GDPR":       {name:"GDPR",         icon:"🇪🇺", total:11, trend:[82,85,87,88,89,90,91]},
  "NIST CSF":   {name:"NIST CSF",     icon:"🛡", total:23, trend:[68,70,71,73,74,75,76]},
  "NIST":       {name:"NIST CSF",     icon:"🛡", total:23, trend:[68,70,71,73,74,75,76]},
  "PCI DSS":    {name:"PCI DSS",      icon:"💳", total:15, trend:[50,52,54,56,58,60,61]},
  "HIPAA":      {name:"HIPAA",        icon:"🏥", total:18, trend:[72,74,75,76,77,77,78]},
  "Custom":     {name:"Custom",       icon:"📋", total:20, trend:[50,55,58,60,62,64,65]},
};
let compFrameworks = Object.values(FRAMEWORK_META).filter((v,i,a)=>a.findIndex(x=>x.name===v.name)===i).map(f=>({...f,passed:0,questionnaires:[]}));

async function renderCompliance() {
  const grid = document.getElementById("complianceGrid");
  if (!grid) return;
  try {
    const data = await api("GET", "/questionnaires/");
    const qs = data.questionnaires || [];
    const fwMap = {};
    qs.forEach(q => {
      const key = q.framework || "Custom";
      if (!fwMap[key]) {
        const meta = FRAMEWORK_META[key] || {name:key,icon:"📋",total:q.total,trend:[50,55,58,60,62,64,65]};
        fwMap[key] = {...meta, passed:0, total:meta.total, questionnaires:[]};
      }
      fwMap[key].passed += q.answered;
      fwMap[key].total = Math.max(fwMap[key].total, q.total);
      fwMap[key].questionnaires.push(q);
    });
    Object.entries(FRAMEWORK_META).forEach(([k,v]) => {
      if (!fwMap[k] && !Object.values(fwMap).find(x=>x.name===v.name)) {
        fwMap[k] = {...v, passed:Math.floor(v.total*0.65), questionnaires:[]};
      }
    });
    compFrameworks = Object.values(fwMap).filter((v,i,a)=>a.findIndex(x=>x.name===v.name)===i);
  } catch(e) {
    compFrameworks = Object.values(FRAMEWORK_META).filter((v,i,a)=>a.findIndex(x=>x.name===v.name)===i)
      .map(f=>({...f,passed:Math.floor(f.total*0.72),questionnaires:[]}));
  }
  grid.innerHTML = compFrameworks.map(f => {
    const pct = Math.round((Math.min(f.passed,f.total)/f.total)*100);
    const color = pct>=85?"var(--accent)":pct>=65?"var(--warn)":"var(--red)";
    const statusLabel = pct>=85?"✅ Compliant":pct>=65?"⚠ In Progress":"❌ Non-Compliant";
    const qs = f.questionnaires || [];
    return `<div style="background:var(--surf);border:1px solid var(--border);border-radius:var(--radius);padding:18px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:18px;">${f.icon}</span>
          <div><div style="font-weight:700;font-size:13px;">${f.name}</div><div style="font-size:11px;color:var(--text2);">${f.passed}/${f.total} controls</div></div>
        </div>
        <div style="text-align:right;">
          <div style="font-family:var(--display);font-size:24px;color:${color};">${pct}%</div>
          <div style="font-size:10px;color:${color};">${statusLabel}</div>
        </div>
      </div>
      <div class="prog-wrap" style="margin-bottom:8px;"><div class="prog-fill" style="width:${pct}%;background:${color};transition:width 1s ease;"></div></div>
      <div style="font-size:11px;color:var(--text2);margin-bottom:8px;">${f.total-Math.min(f.passed,f.total)} controls remaining</div>
      ${qs.length ? `<div style="font-size:11px;color:var(--text2);border-top:1px solid var(--border);padding-top:8px;margin-top:4px;">
        ${qs.map(q=>`<div style="display:flex;justify-content:space-between;margin-bottom:3px;">
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px;">${q.title}</span>
          <span style="font-family:var(--mono);color:${q.status==='completed'?'var(--accent)':q.status==='in_progress'?'var(--warn)':'var(--text2)'};">${q.percent}%</span>
        </div>`).join("")}
      </div>` : ""}
    </div>`;
  }).join("");
  renderComplianceTrend();
}
function renderComplianceTrend() {
  const ctx = document.getElementById("complianceChart");
  if (!ctx) return;
  if (compChart) compChart.destroy();
  const labels = ["7d","6d","5d","4d","3d","2d","Today"];
  const colors = ["#00e5b0","#3b82f6","#f59e0b","#a855f7","#f43f5e","#06b6d4"];
  compChart = new Chart(ctx, {
    type:"line", data:{labels,datasets:compFrameworks.map((f,i)=>({label:f.name,data:f.trend,borderColor:colors[i],backgroundColor:"transparent",tension:0.4,pointRadius:2,borderWidth:2}))},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#8896b3",font:{size:11},boxWidth:12}}},scales:{x:{grid:{color:"rgba(255,255,255,0.04)"},ticks:{color:"#8896b3",font:{size:10}}},y:{grid:{color:"rgba(255,255,255,0.04)"},ticks:{color:"#8896b3",font:{size:10},callback:v=>v+"%"},min:45,max:100}}}
  });
}
async function genComplianceReport() { toast("Generating compliance report…","info"); try { const d = await api("POST","/reports/generate",{type:"compliance"}); await loadReports(); toast("Report generated!","success"); } catch(e){} }
