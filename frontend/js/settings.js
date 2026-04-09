// CyberGuard v2.0 — Settings
function loadSettings() {
  if (!CURRENT_USER) return;
  document.getElementById("set-name").value = CURRENT_USER.name || "";
  document.getElementById("set-email").value = CURRENT_USER.email || "";
  document.getElementById("set-role").value = CURRENT_USER.role || "";
  document.getElementById("set-company").value = CURRENT_USER.company || "";
  document.getElementById("set-domain").value = CURRENT_USER.domain || "";
}
async function saveSettings() {
    const body = {
      name: document.getElementById("set-name").value,
      role: document.getElementById("set-role").value, company: document.getElementById("set-company").value,
      domain: document.getElementById("set-domain").value, password: document.getElementById("set-password").value
    };
  try {
    const d = await api("PUT", "/auth/update", body);
    CURRENT_USER = d;
    document.getElementById("userAv").textContent = d.initials;
    document.getElementById("userName").textContent = d.name;
    document.getElementById("userRole").textContent = d.role;
    toast("Settings saved ✓", "success");
  } catch (e) { toast("Save failed", "error"); }
}
