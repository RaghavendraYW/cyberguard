// CyberGuard v2.5 — VPN & Zero-Trust Perimeter Monitoring
if (typeof escapeHtml !== 'function') {
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }
}
let currentVPNConnections = [];
let vpnFilterStatus = 'all';

async function loadVPN() {
  const container = document.getElementById('vpnTableBody');
  if (container) {
    container.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text3);"><div class="spinner"></div><div style="margin-top:8px;">Fetching VPN gateway & tunnel status…</div></td></tr>';
  }

  try {
    const [statusData, connData] = await Promise.all([
      api('GET', '/vpn/status').catch(err => {
        console.error('VPN status fetch failed:', err);
        return null;
      }),
      api('GET', '/vpn/connections').catch(err => {
        console.error('VPN connections fetch failed:', err);
        return { connections: [] };
      })
    ]);

    if (statusData) {
      renderVPNStats(statusData);
    }

    currentVPNConnections = connData.connections || [];
    renderVPNTable();
  } catch (e) {
    console.error('Error loading VPN dashboard:', e);
    toast('Failed to load VPN status', 'error');
  }
}

function renderVPNStats(data) {
  const stats = data.stats || {};
  const gw = data.gateway || {};

  const activeEl = document.getElementById('vpnActiveTunnels');
  if (activeEl) activeEl.textContent = stats.active_tunnels || 0;

  const complEl = document.getElementById('vpnComplianceRate');
  if (complEl) complEl.textContent = `${stats.compliance_rate || 100}%`;

  const bwEl = document.getElementById('vpnTotalBandwidth');
  if (bwEl) bwEl.textContent = `${stats.total_bandwidth_mb || 0} MB`;

  const latEl = document.getElementById('vpnAvgLatency');
  if (latEl) latEl.textContent = `${stats.avg_latency_ms || 20} ms`;

  // Badge in sidebar
  const badge = document.getElementById('badge-vpn');
  if (badge) {
    badge.textContent = `${stats.active_tunnels || 0} Online`;
  }

  // Gateway card details
  const gwName = document.getElementById('vpnGwName');
  if (gwName) gwName.textContent = gw.name || 'WireGuard Gateway';

  const gwIp = document.getElementById('vpnGwIp');
  if (gwIp) gwIp.textContent = `${gw.gateway_ip || '10.8.0.1'} (${gw.virtual_subnet || '10.8.0.0/24'})`;

  const gwProto = document.getElementById('vpnGwProto');
  if (gwProto) gwProto.textContent = gw.protocol || 'WireGuard';

  const gwDns = document.getElementById('vpnGwDns');
  if (gwDns) gwDns.textContent = gw.dns_protection || 'Active';
}

function filterVPN(status, btn) {
  vpnFilterStatus = status;
  document.querySelectorAll('.vpn-filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderVPNTable();
}

function renderVPNTable() {
  const tbody = document.getElementById('vpnTableBody');
  if (!tbody) return;

  let list = currentVPNConnections;
  if (vpnFilterStatus !== 'all') {
    if (vpnFilterStatus === 'connected' || vpnFilterStatus === 'disconnected') {
      list = list.filter(n => n.status === vpnFilterStatus);
    } else if (vpnFilterStatus === 'quarantine' || vpnFilterStatus === 'compliant') {
      list = list.filter(n => n.posture_status === vpnFilterStatus);
    }
  }

  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text3);">No VPN tunnels match the selected filter.</td></tr>';
    return;
  }

  tbody.innerHTML = list.map(n => {
    const isConn = n.status === 'connected';
    const statusChip = isConn
      ? '<span class="chip chip-success" style="background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.3);padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#10b981;margin-right:4px;"></span>Connected</span>'
      : '<span class="chip" style="background:rgba(148,163,184,0.15);color:var(--text3);border:1px solid var(--border);padding:2px 8px;border-radius:12px;font-size:11px;"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--text3);margin-right:4px;"></span>Offline</span>';

    const postureBadge = n.posture_status === 'compliant'
      ? '<span class="chip chip-blue" style="font-size:11px;">🛡️ Compliant</span>'
      : (n.posture_status === 'quarantine'
        ? '<span class="chip chip-critical" style="font-size:11px;">⚠️ Quarantined</span>'
        : '<span class="chip chip-high" style="font-size:11px;">Non-compliant</span>');

    return `
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:12px 14px;">
          <div style="font-weight:600;color:var(--text1);">${escapeHtml(n.user_name)}</div>
          <div style="font-size:11px;color:var(--text3);">${escapeHtml(n.user_email)}</div>
        </td>
        <td style="padding:12px 14px;">
          <div style="display:flex;align-items:center;gap:6px;">
            <span>💻</span>
            <span style="font-family:var(--mono);font-size:12px;color:var(--text1);">${escapeHtml(n.device_name)}</span>
          </div>
          <div style="font-size:10px;color:var(--text3);">${n.protocol}</div>
        </td>
        <td style="padding:12px 14px;">
          <code style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;font-size:12px;color:var(--accent);">${escapeHtml(n.virtual_ip)}</code>
        </td>
        <td style="padding:12px 14px;">
          <div style="font-size:12px;color:var(--text2);">${escapeHtml(n.endpoint_ip || 'Internal')}</div>
          <div style="font-size:10px;color:var(--text3);">${escapeHtml(n.server_location)}</div>
        </td>
        <td style="padding:12px 14px;">
          ${statusChip}
          <div>
            ${n.is_authenticated ? `
              <span class="chip" style="background:rgba(0,255,204,0.12);color:#00ffcc;border:1px solid rgba(0,255,204,0.3);font-size:10px;padding:1px 6px;border-radius:10px;display:inline-block;margin-top:4px;">🔐 2FA Verified</span>
            ` : `
              <span class="chip" style="background:rgba(234,179,8,0.12);color:#eab308;border:1px solid rgba(234,179,8,0.3);font-size:10px;padding:1px 6px;border-radius:10px;display:inline-block;margin-top:4px;">⚠️ 2FA Required</span>
            `}
          </div>
        </td>
        <td style="padding:12px 14px;">${postureBadge}</td>
        <td style="padding:12px 14px;font-family:var(--mono);font-size:11px;color:var(--text2);">
          ↑ ${n.bytes_sent}MB · ↓ ${n.bytes_received}MB
          <div style="font-size:10px;color:var(--text3);">${n.latency_ms}ms latency</div>
        </td>
        <td style="padding:12px 14px;text-align:right;">
          <div style="display:inline-flex;gap:6px;align-items:center;">
            ${n.is_authenticated ? `
              <button class="btn btn-sm btn-ghost" style="font-size:11px;padding:4px 8px;color:#10b981;border:1px solid rgba(16,185,129,0.3);background:rgba(16,185,129,0.06);" onclick="showNormalUsage(${n.id})" title="Normal Usage Active — Access Intranet">
                🌐 Normal Usage
              </button>
            ` : `
              <button class="btn btn-sm btn-ghost" style="font-size:11px;padding:4px 8px;color:#00ffcc;border:1px solid rgba(0,255,204,0.4);background:rgba(0,255,204,0.06);" onclick="openMfaAuthModal(${n.id})" title="Authenticate with Google / Microsoft Authenticator">
                🔐 2FA Auth
              </button>
            `}
            ${n.posture_status === 'quarantine' ? `
              <button class="btn btn-sm btn-ghost" style="font-size:11px;padding:4px 8px;color:#10b981;border:1px solid rgba(16,185,129,0.3);" onclick="changePosture(${n.id}, 'compliant')" title="Clear Quarantine & Re-authorize">
                🛡️ Release
              </button>
            ` : ''}
            <button class="btn btn-sm ${isConn ? 'btn-ghost' : 'btn-primary'}" style="font-size:11px;padding:4px 8px;" onclick="toggleVPNNode(${n.id})" title="${isConn ? 'Disconnect Tunnel' : 'Connect Tunnel'}">
              ${isConn ? 'Disconnect' : 'Connect'}
            </button>
            <button class="btn btn-sm btn-ghost" style="font-size:11px;padding:4px 8px;" onclick="showVPNConfig(${n.id})" title="View WireGuard Config">
              ⚙️ Conf
            </button>
            <button class="btn btn-sm btn-ghost" style="font-size:11px;padding:4px 8px;color:var(--red);" onclick="revokeVPNNode(${n.id})" title="Revoke Device">
              ✕
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function toggleVPNNode(id) {
  try {
    const res = await api('POST', `/vpn/toggle/${id}`);
    toast(res.message || 'VPN status toggled', 'success');
    await loadVPN();
  } catch (e) {
    toast('Failed to toggle VPN connection', 'error');
  }
}

async function changePosture(id, newPosture) {
  try {
    await api('POST', `/vpn/posture/${id}`, { posture_status: newPosture });
    toast(`Node posture updated to ${newPosture} ✓`, 'success');
    await loadVPN();
  } catch (e) {
    toast('Failed to update posture status', 'error');
  }
}

let activeConfFile = '';
let activeConfContent = '';

async function runVPNConnectivityTest() {
  const btn = document.getElementById('vpnTestFlowBtn');
  const originalHtml = btn ? btn.innerHTML : '⚡ Test End-to-End Flow';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:12px;height:12px;display:inline-block;vertical-align:middle;margin-right:6px;"></span>Testing Handshakes…';
  }

  try {
    const res = await api('POST', '/vpn/test_connectivity');
    toast(`✓ Verified ${res.tested_count} Tunnels: ${res.gateway_health}`, 'success');
    await loadVPN();
  } catch (e) {
    console.error('VPN connectivity test failed:', e);
    toast('VPN connectivity test failed: ' + (e.message || 'Gateway unreachable'), 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

async function showVPNConfig(id) {
  try {
    const res = await api('GET', `/vpn/config/${id}`);
    activeConfFile = res.filename || 'cyberguard-client.conf';
    activeConfContent = res.config || '';

    const textEl = document.getElementById('vpnConfText');
    if (textEl) textEl.value = activeConfContent;

    const titleEl = document.getElementById('vpnConfTitle');
    if (titleEl) titleEl.textContent = `WireGuard Config: ${activeConfFile}`;

    const qrImg = document.getElementById('vpnQrCodeImg');
    const qrWrap = document.getElementById('vpnQrWrapper');
    if (qrImg && res.qr_code) {
      qrImg.src = res.qr_code;
      if (qrWrap) qrWrap.style.display = 'flex';
    } else if (qrWrap) {
      qrWrap.style.display = 'none';
    }

    openModal('vpnConfModal');
  } catch (e) {
    toast('Failed to fetch WireGuard configuration', 'error');
  }
}

function copyVPNConfig() {
  if (!activeConfContent) return;
  const btn = document.getElementById('vpnCopyBtn');
  navigator.clipboard.writeText(activeConfContent).then(() => {
    toast('WireGuard config copied to clipboard! ✓', 'success');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = '✓ Copied!';
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    }
  }).catch(() => {
    toast('Could not copy automatically. Please select text manually.', 'warn');
  });
}

function downloadVPNConfigFile() {
  if (!activeConfContent) return;
  const blob = new Blob([activeConfContent], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = activeConfFile || 'cyberguard-client.conf';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast(`Downloaded ${activeConfFile}`, 'success');
}

function openAddVPNModal() {
  openModal('vpnProvisionModal');
}

async function submitProvisionVPN() {
  const name = document.getElementById('vpn-prov-name')?.value.trim();
  const email = document.getElementById('vpn-prov-email')?.value.trim();
  const device = document.getElementById('vpn-prov-device')?.value.trim();
  const proto = document.getElementById('vpn-prov-proto')?.value || 'WireGuard';
  const loc = document.getElementById('vpn-prov-loc')?.value || 'US-East Gateway';

  if (!name || !email || !device) {
    toast('Please fill in Name, Email, and Device', 'warn');
    return;
  }

  try {
    const res = await api('POST', '/vpn/connections', {
      user_name: name,
      user_email: email,
      device_name: device,
      protocol: proto,
      server_location: loc
    });
    toast(`Provisioned VPN tunnel on ${res.virtual_ip}! ✓`, 'success');
    closeModal('vpnProvisionModal');
    // Clear form
    if (document.getElementById('vpn-prov-name')) document.getElementById('vpn-prov-name').value = '';
    if (document.getElementById('vpn-prov-email')) document.getElementById('vpn-prov-email').value = '';
    if (document.getElementById('vpn-prov-device')) document.getElementById('vpn-prov-device').value = '';
    await loadVPN();
  } catch (e) {
    toast('Failed to provision VPN node', 'error');
  }
}

async function revokeVPNNode(id) {
  if (!confirm('Are you sure you want to revoke this VPN node and terminate all access?')) return;
  try {
    await api('DELETE', `/vpn/connections/${id}`);
    toast('VPN tunnel revoked and removed', 'success');
    await loadVPN();
  } catch (e) {
    toast('Failed to revoke VPN node', 'error');
  }
}

function toggleKillswitch() {
  const ksBtn = document.getElementById('vpnKillswitchBtn');
  const isEnforced = ksBtn?.dataset?.enforced === 'true';
  const next = !isEnforced;

  if (ksBtn) {
    ksBtn.dataset.enforced = next ? 'true' : 'false';
    ksBtn.textContent = next ? '🛡️ Killswitch: ENFORCED' : '⚠️ Killswitch: PERMISSIVE';
    ksBtn.className = next ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost';
  }
  toast(next ? 'Zero-trust killswitch ENFORCED: Outbound traffic blocked if VPN drops' : 'Zero-trust killswitch set to permissive', next ? 'success' : 'warn');
}


// ── Zero-Trust MFA Authenticator Logic ────────────────────────
let currentMfaSetup = null;

async function openMfaAuthModal(connId) {
  try {
    const res = await api('GET', `/vpn/mfa/setup/${connId}`);
    currentMfaSetup = res;

    const connIdEl = document.getElementById('mfaConnId');
    if (connIdEl) connIdEl.value = res.connection_id;

    const devLabel = document.getElementById('mfaDeviceLabel');
    if (devLabel) devLabel.textContent = `Device: ${res.device_name}`;

    const userLabel = document.getElementById('mfaUserLabel');
    if (userLabel) userLabel.textContent = res.user_email;

    const ipLabel = document.getElementById('mfaIpLabel');
    if (ipLabel) ipLabel.textContent = res.virtual_ip;

    const qrImg = document.getElementById('mfaQrImg');
    if (qrImg) qrImg.src = res.qr_code;

    const secretKey = document.getElementById('mfaSecretKey');
    if (secretKey) secretKey.textContent = res.secret;

    const testPreview = document.getElementById('mfaTestCodePreview');
    if (testPreview) testPreview.textContent = res.test_code;

    const codeInp = document.getElementById('mfaCodeInput');
    if (codeInp) {
      codeInp.value = '';
      setTimeout(() => codeInp.focus(), 150);
    }

    const feedback = document.getElementById('mfaFeedback');
    if (feedback) feedback.style.display = 'none';

    openModal('vpnMfaModal');
  } catch (e) {
    console.error('Failed to load MFA setup:', e);
    toast('Failed to load Zero-Trust MFA profile', 'error');
  }
}

function useTestCode() {
  const testPreview = document.getElementById('mfaTestCodePreview');
  const codeInp = document.getElementById('mfaCodeInput');
  if (testPreview && codeInp) {
    codeInp.value = testPreview.textContent.trim();
    toast('Auto-filled current TOTP code', 'info');
  }
}

async function submitMfaVerify() {
  const connId = parseInt(document.getElementById('mfaConnId')?.value || '0', 10);
  const code = document.getElementById('mfaCodeInput')?.value.trim();
  const feedback = document.getElementById('mfaFeedback');
  const btn = document.getElementById('mfaVerifyBtn');

  if (!code || code.length < 6) {
    toast('Please enter a valid 6-digit Authenticator code', 'warn');
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:12px;height:12px;display:inline-block;vertical-align:middle;margin-right:6px;"></span>Verifying…';
  }

  try {
    const res = await api('POST', '/vpn/mfa/verify', { connection_id: connId, code: code });
    toast(`✓ ${res.message}`, 'success');
    closeModal('vpnMfaModal');
    await loadVPN();
  } catch (e) {
    console.error('MFA verification error:', e);
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'rgba(239,68,68,0.12)';
      feedback.style.color = '#ef4444';
      feedback.style.border = '1px solid rgba(239,68,68,0.3)';
      feedback.innerHTML = `<strong>⚠️ Authentication Failed:</strong> ${e.message || 'Invalid code. Access Denied (MITRE T1110 logged).'}`;
    }
    toast('Invalid Authenticator code — Access Denied', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Verify & Authorize Tunnel';
    }
  }
}

function showNormalUsage(connId) {
  const node = currentVPNConnections.find(n => n.id === connId);
  if (!node) return;

  const titleEl = document.getElementById('nuModalTitle');
  if (titleEl) titleEl.textContent = `Zero-Trust Normal Usage: ${node.device_name}`;

  const bodyEl = document.getElementById('nuModalBody');
  if (bodyEl) {
    bodyEl.innerHTML = `
      <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);border-radius:10px;padding:14px;margin-bottom:16px;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
          <span style="font-size:20px;">🛡️</span>
          <div>
            <div style="font-size:14px;font-weight:700;color:#10b981;">Tunnel Authorized & Active</div>
            <div style="font-size:11px;color:var(--text2);">Multi-Factor Authentication Verified via RFC 6238 TOTP</div>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px;font-size:12px;">
          <div><span style="color:var(--text3);">Assigned IP:</span> <strong style="color:var(--accent);font-family:var(--mono);">${node.virtual_ip}</strong></div>
          <div><span style="color:var(--text3);">Gateway:</span> <strong>10.8.0.1 (wg0)</strong></div>
          <div><span style="color:var(--text3);">Latency:</span> <strong>${node.latency_ms}ms</strong></div>
          <div><span style="color:var(--text3);">Posture:</span> <strong style="color:#10b981;">Compliant</strong></div>
        </div>
      </div>

      <div style="font-size:12px;font-weight:700;color:var(--text1);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">Authorized Enterprise Resources (Normal Usage)</div>
      <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:14px;">
        <div style="padding:10px;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:6px;display:flex;justify-content:space-between;align-items:center;">
          <div>
            <div style="font-weight:600;font-size:12px;color:var(--text1);">🏢 Internal Intranet Portal</div>
            <div style="font-size:11px;color:var(--text3);font-family:var(--mono);">http://10.8.0.1:8000/dashboard</div>
          </div>
          <span class="chip chip-success" style="font-size:10px;">Allowed</span>
        </div>
        <div style="padding:10px;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:6px;display:flex;justify-content:space-between;align-items:center;">
          <div>
            <div style="font-weight:600;font-size:12px;color:var(--text1);">🔍 Threat Defense & SIEM Feed</div>
            <div style="font-size:11px;color:var(--text3);font-family:var(--mono);">http://10.8.0.1:8000/threats</div>
          </div>
          <span class="chip chip-success" style="font-size:10px;">Allowed</span>
        </div>
        <div style="padding:10px;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:6px;display:flex;justify-content:space-between;align-items:center;">
          <div>
            <div style="font-weight:600;font-size:12px;color:var(--text1);">🛡️ Malware DNS Shield</div>
            <div style="font-size:11px;color:var(--text3);font-family:var(--mono);">1.1.1.2 (Cloudflare Zero-Trust)</div>
          </div>
          <span class="chip chip-blue" style="font-size:10px;">Enforced</span>
        </div>
      </div>
    `;
  }
  openModal('vpnNormalUsageModal');
}

let activeGwConfContent = '';

async function showGatewayConfig() {
  try {
    const res = await api('GET', '/vpn/gateway/config');
    activeGwConfContent = res.config || '';

    const textEl = document.getElementById('vpnGwConfText');
    if (textEl) textEl.value = activeGwConfContent;

    const titleEl = document.getElementById('vpnGwConfTitle');
    if (titleEl) titleEl.textContent = `Server Gateway Config: ${res.filename} (${res.peer_count} Peers)`;

    openModal('vpnGatewayModal');
  } catch (e) {
    toast('Failed to fetch Gateway server configuration', 'error');
  }
}

function copyGatewayConfig() {
  if (!activeGwConfContent) return;
  const btn = document.getElementById('vpnGwCopyBtn');
  navigator.clipboard.writeText(activeGwConfContent).then(() => {
    toast('Gateway server config copied to clipboard! ✓', 'success');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = '✓ Copied!';
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    }
  }).catch(() => {
    toast('Could not copy automatically. Select text manually.', 'warn');
  });
}

function downloadGatewayConfigFile() {
  if (!activeGwConfContent) return;
  const blob = new Blob([activeGwConfContent], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'cyberguard-gateway.conf';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast('Downloaded cyberguard-gateway.conf', 'success');
}

