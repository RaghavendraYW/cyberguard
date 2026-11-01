"""
CyberGuard v3.0 — Employee Monitoring Routes (trimmed)
Active-window streaming REMOVED. This module now handles:
  - Agent authentication key management
  - Posture-only fleet user list (no screen content)
  - Optional demo-mode label (off by default, admin-controlled)

Security events and posture checks are handled by /api/threats and /api/posture.
See routes/threat_detection.py and backend/detection.py.
"""
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, UserDB, DevicePostureDB, VPNConnectionDB
from auth import get_uid, get_admin

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


@router.get("/users")
def get_monitored_users(uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    """
    Fleet user list for the admin panel.
    Returns posture score + VPN status per user.
    Does NOT return active_window or screen contents.
    """
    users = db.query(UserDB).all()
    results = []

    for u in users:
        # Latest posture record
        posture = (
            db.query(DevicePostureDB)
            .filter_by(user_email=u.email)
            .order_by(DevicePostureDB.last_checked.desc())
            .first()
        )
        # VPN node
        vpn = db.query(VPNConnectionDB).filter_by(user_email=u.email).first()

        results.append({
            "id":             u.id,
            "name":           u.name,
            "email":          u.email,
            "role":           u.role,
            "tracking_key":   u.tracking_key,
            "last_seen":      u.last_seen.isoformat() + "Z" if u.last_seen else None,
            # Posture (security telemetry — not surveillance)
            "posture_score":  posture.posture_score if posture else None,
            "posture_risk":   posture.risk_level    if posture else "unknown",
            "device_name":    posture.device_name   if posture else None,
            "posture_source": posture.source        if posture else None,
            # VPN
            "vpn_status":     vpn.status            if vpn else "no_vpn",
            "vpn_posture":    vpn.posture_status     if vpn else None,
            "virtual_ip":     vpn.virtual_ip         if vpn else None,
        })

    return {"employees": results}


@router.post("/generate-key/{user_id}")
def generate_tracking_key(
    user_id: int,
    uid: int = Depends(get_admin),
    db: Session = Depends(get_db),
):
    """Generate or rotate the agent authentication key for a user."""
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(404, "User not found")

    new_key = f"cg_trk_{secrets.token_urlsafe(16)}"
    u.tracking_key = new_key
    db.commit()

    return {"id": u.id, "tracking_key": u.tracking_key}


# ── Telemetry & Threat Ingest Route ─────────────────────────────
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import detection as det
from database import ActivityLogDB

class MonitoringIngestReq(BaseModel):
    tracking_key: str
    active_window: Optional[str] = "Desktop"
    status: Optional[str] = "active"


@router.post("/ingest")
def ingest_monitoring_telemetry(req: MonitoringIngestReq, db: Session = Depends(get_db)):
    """
    Ingest endpoint telemetry from coworker/friend machine.
    Evaluates process/window signatures for malicious tools (Mimikatz, Wireshark, Tor, etc.)
    and enforces instant automated Zero-Trust quarantine and incident creation.
    """
    if not req.tracking_key or not req.tracking_key.strip():
        raise HTTPException(401, "Tracking key is required")

    user = db.query(UserDB).filter_by(tracking_key=req.tracking_key.strip()).first()
    if not user:
        raise HTTPException(401, "Invalid tracking key")

    user.last_seen = datetime.now(timezone.utc)
    title = (req.active_window or "").strip()
    title_lower = title.lower()

    # Threat Signatures
    THREAT_SIGNATURES = [
        ("mimikatz", "Mimikatz LSASS Credential Dumper", "credential_tool"),
        ("wireshark", "Promiscuous Packet Capture Tool", "credential_tool"),
        ("tor", "Tor Anonymizing Proxy / Darknet Exfiltration", "malicious_dns"),
        ("metasploit", "Metasploit Exploit Framework", "credential_tool"),
        ("nmap", "Nmap Network Scanning & Enumeration", "unusual_resource_access"),
        ("powershell -enc", "Obfuscated Encoded PowerShell Execution", "credential_tool"),
        ("hashcat", "Hashcat Password Recovery Tool", "credential_tool"),
        ("lazagne", "LaZagne Credential Harvester", "credential_tool"),
        ("c2", "Command & Control Communication Beacon", "malicious_dns"),
        ("cobaltstrike", "Cobalt Strike Beacon", "malicious_dns"),
    ]

    detected_threat = None
    for pattern, name, rule_key in THREAT_SIGNATURES:
        if pattern in title_lower:
            detected_threat = (name, rule_key)
            break

    if detected_threat:
        threat_name, rule_key = detected_threat
        peer_node = db.query(VPNConnectionDB).filter_by(user_email=user.email).first()
        peer_ip = peer_node.virtual_ip if peer_node else ""

        # 1. Fire threat event in SIEM engine
        details = f"[Agent Detection] Malicious process detected on {user.name}'s workstation: '{title}'. Automated Zero-Trust quarantine enforced."
        event = det._fire_event(db, rule_key, user.email, peer_ip, details, source="endpoint_agent")

        # 2. Fire high-priority Alert in SOC panel
        det._fire_alert(db, rule_key, user.email, details)

        # 3. Auto-quarantine peer node (sever VPN tunnel & active killswitch)
        det._quarantine_peer(db, user.email)

        # 4. Deduct security score
        risk_delta = det.RULES.get(rule_key, {}).get("risk_delta", -50)
        det._deduct_org_score(db, risk_delta)

        # 5. Log anomaly in Activity Log
        db.add(ActivityLogDB(
            user_email=user.email,
            action="threat_detected",
            ip_address=peer_ip or "127.0.0.1",
            user_agent="CyberGuard Endpoint Agent",
            page="Fleet Threat Detection",
            device_info=title[:80],
            is_anomaly=True,
            anomaly_score=0.99
        ))
        db.commit()

        return {
            "status": "threat_detected",
            "threat": threat_name,
            "severity": "critical",
            "posture": "quarantine",
            "user": user.name,
            "rule": rule_key,
            "event_id": event.id if event else None,
            "quarantined": True
        }

    # Safe telemetry ping / restore
    db.commit()
    return {
        "status": "active",
        "threat": None,
        "severity": "none",
        "posture": "compliant",
        "user": user.name
    }

