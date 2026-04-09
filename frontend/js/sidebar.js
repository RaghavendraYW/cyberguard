// CyberGuard v2.0 — Sidebar & Navigation
function toggleSidebar() {
  const sb = document.querySelector(".sidebar");
  const isCollapsed = sb.classList.toggle("collapsed");
  localStorage.setItem("cg_sidebar", isCollapsed ? "collapsed" : "expanded");
  document.querySelector(".topbar").classList.toggle("sb-collapsed", isCollapsed);
  document.querySelector(".main-right").classList.toggle("sb-collapsed", isCollapsed);
}
function applySidebarState() {
  if (localStorage.getItem("cg_sidebar") === "collapsed") {
    document.querySelector(".sidebar").classList.add("collapsed");
    document.querySelector(".topbar").classList.add("sb-collapsed");
    document.querySelector(".main-right").classList.add("sb-collapsed");
  }
}
function goPage(page, el) {
  document.querySelectorAll(".page").forEach(p => p.classList.add("page-hidden"));
  document.getElementById("page-" + page)?.classList.remove("page-hidden");
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  if (el) el.classList.add("active");
  document.getElementById("pageTitle").textContent = (el?.dataset?.label || page).trim();
  renderPage(page);
  trackAction("view_" + page);
}
async function renderPage(page) {
  switch (page) {
    case "dashboard": await loadDashboard(); break;
    case "vendors": await loadVendors(); break;
    case "alerts": await loadAlerts(); break;
    case "leaks": await loadLeaks(); break;
    case "anomalies": await loadAnomalies(); break;
    case "questionnaires": await loadQuestionnaires(); break;
    case "reports": await loadReports(); break;
    case "settings": loadSettings(); break;
    case "admin": await loadAdmin(); break;
    case "insider": await loadInsider(); break;
  }
}
async function initApp() {
  applySidebarState();
  document.getElementById("userAv").textContent = CURRENT_USER?.initials || "??";
  document.getElementById("userName").textContent = CURRENT_USER?.name || "User";
  if (document.getElementById("userRole")) {
    document.getElementById("userRole").textContent = CURRENT_USER.role;
  }
  const ag = document.getElementById("adminNavGroup");
  if (ag) {
    if (CURRENT_USER?.isAdmin) ag.style.display = "block";
    else ag.style.display = "none";
  }
  renderAttack();
  renderCompliance();
  await loadDashboard();
  await updateBadges();
}
