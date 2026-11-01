// CyberGuard v2.0 — Auth
async function doLogin() {
  const emailInp = document.getElementById("loginEmail");
  const passInp  = document.getElementById("loginPass");
  const errEl    = document.getElementById("loginError");
  const btn      = document.getElementById("btnLogin") || document.querySelector(".btn-login");

  const email = (emailInp ? emailInp.value : "").trim();
  const pass  = (passInp ? passInp.value : "").trim();

  if (!email) {
    if (errEl) { errEl.textContent = "Please enter your email or username."; errEl.style.display = "block"; }
    return;
  }
  if (!pass) {
    if (errEl) { errEl.textContent = "Please enter your password."; errEl.style.display = "block"; }
    return;
  }

  if (errEl) errEl.style.display = "none";
  let origText = "Sign In →";
  if (btn) {
    origText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span style="display:inline-block;width:14px;height:14px;border:2px solid #000;border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite;margin-right:8px;vertical-align:middle;"></span> Signing in...';
  }

  try {
    const d = await api("POST", "/auth/login", { email, password: pass });
    TOKEN = d.token;
    CURRENT_USER = d.user;

    localStorage.setItem("cg_token", TOKEN);
    localStorage.setItem("TOKEN", TOKEN);
    localStorage.setItem("cg_user", JSON.stringify(CURRENT_USER));
    sessionStorage.setItem("cg_authenticated", "1");

    showApp();
    await initApp();
    if (typeof startBadgePolling === 'function') startBadgePolling();
    if (typeof updateAttackSurfaceStats === 'function') updateAttackSurfaceStats();
    if (typeof initGlobalSearch === 'function') initGlobalSearch();
    trackAction("login");
  } catch (e) {
    if (errEl) {
      errEl.style.display = "block";
      errEl.textContent = e.message || "Invalid credentials. Try again.";
      setTimeout(() => { if (errEl) errEl.style.display = "none"; }, 5000);
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = origText;
    }
  }
}

function quickFill(email, pass) {
  const emailInp = document.getElementById("loginEmail");
  const passInp  = document.getElementById("loginPass");
  const errEl    = document.getElementById("loginError");
  if (emailInp) emailInp.value = email;
  if (passInp)  passInp.value  = pass;
  if (errEl)    errEl.style.display = "none";
}

function togglePassVisibility() {
  const passInp = document.getElementById("loginPass");
  if (!passInp) return;
  passInp.type = passInp.type === "password" ? "text" : "password";
}

function doLogout() {
  try {
    api("POST", "/auth/logout").catch(() => {});
  } catch (e) {}

  TOKEN = "";
  CURRENT_USER = null;
  localStorage.clear();
  sessionStorage.clear();

  showLogin();
  quickFill("admin@company.com", "Admin@1234");
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const loginPage = document.getElementById("loginPage");
    if (loginPage && loginPage.style.display !== "none") {
      doLogin();
    }
  }
});
