// CyberGuard v2.0 — Auth
async function doLogin() {
  const email = document.getElementById("loginEmail").value.trim();
  const pass  = document.getElementById("loginPass").value;
  try {
    const d = await api("POST", "/auth/login", { email, password: pass });
    TOKEN = d.token; CURRENT_USER = d.user;
    localStorage.setItem("cg_token", TOKEN); localStorage.setItem("cg_user", JSON.stringify(CURRENT_USER));
    document.getElementById("loginPage").style.display = "none";
    document.getElementById("app").style.display = "block";
    initApp();
    trackAction("login");
  } catch (e) {
    const el = document.getElementById("loginError"); el.style.display = "block"; el.textContent = e.message;
    setTimeout(() => el.style.display = "none", 3000);
  }
}
function doLogout() { TOKEN = ""; CURRENT_USER = null; localStorage.removeItem("cg_token"); localStorage.removeItem("cg_user"); location.reload(); }
document.addEventListener("keydown", e => { if (e.key === "Enter" && document.getElementById("loginPage").style.display !== "none") doLogin(); });
