// CyberGuard v2.0 — Startup
document.addEventListener("DOMContentLoaded", function() {
  const savedToken = localStorage.getItem("cg_token");
  const savedUser = localStorage.getItem("cg_user");
  if (savedToken && savedUser) {
    TOKEN = savedToken;
    CURRENT_USER = JSON.parse(savedUser);
    document.getElementById("loginPage").style.display = "none";
    document.getElementById("app").style.display = "flex";
    initApp();
  } else {
    TOKEN = ""; CURRENT_USER = null;
    document.getElementById("loginPage").style.display = "flex";
    document.getElementById("app").style.display = "none";
  }
});
