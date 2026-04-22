// CyberGuard v2.0 — Admin Monitoring
let adminRefreshTimer = null;

async function loadAdmin() {
  try {
    const [stats, users, feed, monitoringResponse] = await Promise.all([
      api("GET", "/admin/stats"), api("GET", "/admin/users"), api("GET", "/admin/activity-feed?limit=50"),
      api("GET", "/monitoring/users").catch(() => ({employees: []}))
    ]);
    document.getElementById("adminTotalUsers").textContent = stats.totalUsers || 0;
    document.getElementById("adminOnline").textContent     = stats.onlineNow || 0;
    document.getElementById("adminTodayLogs").textContent  = stats.todayLogs || 0;
    document.getElementById("adminAnomalies").textContent  = stats.totalAnomalies || 0;
    document.getElementById("badge-online").textContent    = stats.onlineNow || 0;
    const mergedUsers = users.users.map(u => {
      const mon = monitoringResponse.employees.find(x => x.id === u.id) || {};
      return { ...u, activeWindow: mon.active_window || "—", trackingKey: mon.tracking_key };
    });
    renderAdminUsers(mergedUsers);
    renderAdminFeed(feed.feed || []);
    if (adminRefreshTimer) clearTimeout(adminRefreshTimer);
    adminRefreshTimer = setTimeout(() => {
      if (document.querySelector(".nav-item.active")?.dataset?.page === "admin") loadAdmin();
    }, 10000);
  } catch(e) {
    renderAdminUsersFallback();
    renderAdminFeedFallback();
  }
}

function renderAdminUsers(users) {
  const tbody = document.getElementById("adminUsersTable");
  if (!tbody) return;
  tbody.innerHTML = users.map(u => {
    const riskColor = {critical:"var(--red)",high:"var(--warn)",low:"var(--accent)"}[u.riskLevel] || "var(--text2)";
    const onlineNow = u.lastSeen && (Date.now() - new Date(u.lastSeen).getTime()) < 300000;
    return `<tr>
      <td><div style="display:flex;align-items:center;gap:10px;">
          <div style="position:relative;">
            <div style="width:32px;height:32px;border-radius:8px;background:rgba(0,229,176,0.15);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:var(--accent);">${u.initials}</div>
            ${onlineNow ? '<div style="position:absolute;bottom:-2px;right:-2px;width:8px;height:8px;border-radius:50%;background:var(--accent);border:2px solid var(--surf1);"></div>' : ''}
          </div>
          <div><div style="font-size:13px;font-weight:600;">${u.name}</div><div style="font-size:11px;color:var(--text2);">${u.email}</div></div>
        </div></td>
      <td><span class="chip chip-info">${u.role}</span></td>
      <td><span style="font-family:var(--mono);font-size:11px;color:var(--warn);">${u.lastAction || "—"}</span></td>
      <td style="font-size:11px;color:var(--text2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${u.activeWindow}">${u.activeWindow || "—"}</td>
      <td style="font-family:var(--mono);font-size:11px;">${u.lastIp || "—"}</td>
      <td style="font-size:11px;">${u.lastDevice || "—"}</td>
      <td style="font-size:11px;color:var(--text2);">${u.lastSeen ? timeAgo(u.lastSeen) : "Never"}</td>
      <td>
        ${u.trackingKey ? `<span style="font-family:var(--mono);font-size:9px;color:var(--accent);">${u.trackingKey}</span>` : `<button class="btn btn-ghost btn-sm" onclick="generateTrackingKey(${u.id})">Generate Key</button>`}
      </td>
      <td><div style="display:flex;gap:4px;">
          <button class="btn btn-ghost btn-sm" onclick="viewUserActivity('${u.email}','${u.name}')">📋 Logs</button>
          ${!u.isAdmin ? `<button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id},'${u.name}')">🗑</button>` : '<span style="font-size:10px;color:var(--accent);">ADMIN</span>'}
        </div></td>
    </tr>`;
  }).join("");
}

function renderAdminFeed(feed) {
  const el = document.getElementById("adminFeed");
  if (!el) return;
  if (!feed.length) { el.innerHTML = '<div class="empty-state"><div class="empty-icon">📡</div><div class="empty-text">No activity yet</div></div>'; return; }
  el.innerHTML = feed.map(l => {
    const aBadge = l.isAnomaly ? `<span style="font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(244,63,94,0.15);color:var(--red);margin-left:6px;">⚠ anomaly ${(l.anomalyScore*100).toFixed(0)}%</span>` : "";
    return `<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-bottom:1px solid var(--border);font-size:12px;">
      <span style="font-family:var(--mono);font-size:10px;color:var(--text2);min-width:130px;" title="${formatTimestamp(l.timestamp)}">${formatTimestamp(l.timestamp)}</span>
      <span style="font-weight:600;min-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${l.userEmail.split("@")[0]}</span>
      <span style="font-family:var(--mono);color:var(--accent);min-width:120px;">${l.action}</span>
      <span style="color:var(--text2);min-width:80px;">${l.page || "—"}</span>
      <span style="font-family:var(--mono);font-size:10px;color:var(--text2);">${l.ipAddress || "—"}</span>
      <span style="font-size:11px;color:var(--text2);">${l.deviceInfo || "—"}</span>
      ${aBadge}
    </div>`;
  }).join("");
}

async function viewUserActivity(email, name) {
  try {
    const d = await api("GET", `/admin/user/${encodeURIComponent(email)}/activity`);
    const popup = document.createElement("div");
    popup.id = "__userLogPopup";
    popup.style.cssText = "position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--surf);border:1px solid var(--border);border-radius:16px;padding:0;z-index:9999;width:600px;max-height:80vh;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,0.5)";
    popup.innerHTML = `
      <div style="padding:20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <div><div style="font-weight:700;font-size:15px;">${name} — Activity Log</div>
        <div style="font-size:11px;color:var(--text2);margin-top:2px;">${d.totalLogs} actions · ${d.anomalyCount} anomalies</div></div>
        <div style="display:flex;gap:12px;align-items:center;">
          <a href="/api/admin/user/${encodeURIComponent(email)}/download-logs" download target="_blank" style="text-decoration:none;">
            <button style="background:var(--accent);color:#000;border:none;padding:6px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">📥 Download CSV</button>
          </a>
          <button onclick="document.getElementById('__userLogPopup').remove();document.getElementById('__bd').remove();document.body.style.overflow='';" style="background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;">✕</button>
        </div>
      </div>
      <div style="overflow-y:auto;flex:1;">
        ${d.logs.slice(0,30).map(l=>`<div style="display:flex;gap:10px;padding:8px 20px;border-bottom:1px solid var(--border);font-size:11px;${l.isAnomaly?'background:rgba(244,63,94,0.04)':''}">
          <span style="font-family:var(--mono);color:var(--text2);min-width:90px;" title="${formatTimestamp(l.timestamp)}">${formatTimestamp(l.timestamp)}</span>
          <span style="font-family:var(--mono);color:var(--accent);min-width:110px;">${l.action}</span>
          <span style="color:var(--text2);min-width:70px;">${l.page||"—"}</span>
          <span style="font-family:var(--mono);min-width:90px;">${l.ipAddress||"—"}</span>
          <span>${l.deviceInfo||"—"}</span>
          ${l.isAnomaly?`<span style="color:var(--red);margin-left:auto;">⚠ ${(l.anomalyScore*100).toFixed(0)}%</span>`:""}
        </div>`).join("")}
      </div>`;
    const bd = document.createElement("div");
    bd.id = "__bd"; bd.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:9998;";
    bd.onclick = () => { popup.remove(); bd.remove(); document.body.style.overflow = ''; };
    document.body.style.overflow = 'hidden';
    document.body.appendChild(bd); document.body.appendChild(popup);
  } catch(e) { toast("Could not load user activity", "error"); }
}

async function deleteUser(id, name) {
  if (requiresBackend("Delete User")) return;
  if (!confirm(`Delete user "${name}"? This cannot be undone.`)) return;
  try { await api("DELETE", `/admin/users/${id}`); toast(`User ${name} deleted`, "success"); loadAdmin(); } catch(e) { toast("Delete failed", "error"); }
}

async function createUser() {
  if (requiresBackend("Create User")) return;
  const name    = document.getElementById("nu-name").value.trim();
  const email   = document.getElementById("nu-email").value.trim();
  const pass    = document.getElementById("nu-pass").value || "password123";
  const role    = document.getElementById("nu-role").value.trim() || "Analyst";
  const isAdmin = document.getElementById("nu-admin").checked;
  if (!name || !email) { toast("Name and email required", "error"); return; }
  if (!email.includes("@")) { toast("Enter a valid email", "error"); return; }
  try {
    await api("POST", "/admin/users/create", { name, email, password: pass, role, isAdmin, company: "Acme Corp" });
    closeModal("addUserModal");
    ["nu-name","nu-email","nu-role"].forEach(id => document.getElementById(id).value = "");
    document.getElementById("nu-pass").value = "password123";
    document.getElementById("nu-admin").checked = false;
    toast(`✅ User "${name}" created! Login: ${email} / ${pass}`, "success");
    loadAdmin();
  } catch(e) {
    const msg = e.message || "Create failed";
    toast(msg.includes("already exists") ? `Email ${email} is already registered` : msg, "error");
  }
}

async function toggleAdmin(userId, currentIsAdmin, userName) {
  if (requiresBackend("Promote to Admin")) return;
  const makeAdmin = !currentIsAdmin;
  if (!confirm(`${makeAdmin ? "Grant" : "Revoke"} admin access for "${userName}"?`)) return;
  try { await api("PUT", `/admin/users/${userId}`, { isAdmin: makeAdmin }); toast(`${userName} is ${makeAdmin ? "now an admin" : "no longer admin"}`, "success"); loadAdmin(); } catch(e) { toast("Update failed", "error"); }
}

// Demo fallbacks
async function generateTrackingKey(userId) {
  if (requiresBackend("Generate Tracking Key")) return;
  try {
    await api("POST", `/monitoring/generate-key/${userId}`);
    toast("Tracking key generated", "success");
    loadAdmin();
  } catch(e) { toast("Failed to generate key", "error"); }
}

function renderAdminUsersFallback() {
  document.getElementById("adminTotalUsers").textContent = 5;
  document.getElementById("adminOnline").textContent = 2;
  document.getElementById("adminTodayLogs").textContent = 47;
  document.getElementById("adminAnomalies").textContent = 11;
  document.getElementById("badge-online").textContent = 2;
  const demoUsers = [
    {initials:"AK",name:"Alex Kumar",email:"admin@company.com",role:"Security Analyst",lastAction:"view_dashboard",lastPage:"dashboard",lastIp:"192.168.1.5",lastDevice:"Windows PC",lastSeen:new Date(Date.now()-60000).toISOString(),riskLevel:"low",anomalyCount:0,isAdmin:true},
    {initials:"PS",name:"Priya Sharma",email:"priya@company.com",role:"IT Analyst",lastAction:"export_report",lastPage:"reports",lastIp:"192.168.1.12",lastDevice:"MacBook",lastSeen:new Date(Date.now()-120000).toISOString(),riskLevel:"low",anomalyCount:1,isAdmin:false},
    {initials:"RV",name:"Rahul Verma",email:"rahul@company.com",role:"DevOps Engineer",lastAction:"login",lastPage:"login",lastIp:"192.168.1.18",lastDevice:"Linux",lastSeen:new Date(Date.now()-600000).toISOString(),riskLevel:"high",anomalyCount:4,isAdmin:false},
    {initials:"SK",name:"Sara Khan",email:"sara@company.com",role:"Security Engineer",lastAction:"scan_domain",lastPage:"attack",lastIp:"192.168.1.22",lastDevice:"Windows PC",lastSeen:new Date(Date.now()-3600000).toISOString(),riskLevel:"low",anomalyCount:0,isAdmin:false},
    {initials:"JW",name:"James Wilson",email:"james@company.com",role:"Network Admin",lastAction:"delete_vendor",lastPage:"vendors",lastIp:"10.0.0.45",lastDevice:"Windows PC",lastSeen:new Date(Date.now()-7200000).toISOString(),riskLevel:"critical",anomalyCount:7,isAdmin:false},
  ];
  renderAdminUsers(demoUsers);
}

function renderAdminFeedFallback() {
  const actions = ["login","view_dashboard","export_report","scan_domain","delete_vendor","add_vendor","view_dashboard","export_report"];
  const users   = ["admin@company.com","priya@company.com","rahul@company.com","james@company.com"];
  const ips     = ["192.168.1.5","192.168.1.12","192.168.1.18","10.0.0.45"];
  const devices = ["Windows PC","MacBook","Linux","Windows PC"];
  const feed = Array.from({length:20},(_,i)=>({
    userEmail: users[i%4], action: actions[i%8], page: ["dashboard","reports","vendors","attack"][i%4],
    ipAddress: ips[i%4], deviceInfo: devices[i%4], timestamp: new Date(Date.now()-i*120000).toISOString(),
    isAnomaly: i===2||i===7, anomalyScore: i===2||i===7 ? 0.92 : 0.1
  }));
  renderAdminFeed(feed);
}

async function refreshAdmin() { toast("Refreshing admin panel…","info"); await loadAdmin(); toast("Admin panel refreshed ✓","success"); }

