// CyberGuard v2.0 — Helper Functions
function timeAgo(iso) {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "Just now";
  if (diff < 3600) return Math.floor(diff/60) + "m ago";
  if (diff < 86400) return Math.floor(diff/3600) + "h ago";
  return Math.floor(diff/86400) + "d ago";
}
function formatTimestamp(iso) {
  if (!iso) return "—";
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: true, timeZoneName: "short"
    }).format(new Date(iso));
  } catch(e) { return new Date(iso).toLocaleString(); }
}
function downloadCSV(rows, filename) {
  const content = rows.map(r => r.map(c => `"${(c||"").toString().replace(/"/g,'""')}"`).join(",")).join("\n");
  const blob = new Blob([content], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
  toast(filename + " downloaded", "success");
}
function openModal(id) { document.getElementById(id).style.display = "flex"; document.body.style.overflow = "hidden"; }
function closeModal(id) { document.getElementById(id).style.display = "none"; document.body.style.overflow = ""; }
function closeBg(e, id) { if (e.target === document.getElementById(id)) closeModal(id); }
function toast(msg, type = "info") {
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span>${{success:"✓",error:"✕",info:"ℹ",warn:"⚠"}[type]||"ℹ"}</span><span>${msg}</span>`;
  document.getElementById("toastContainer").appendChild(el);
  setTimeout(() => el.remove(), 3200);
}
