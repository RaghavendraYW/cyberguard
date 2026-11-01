"""
CyberGuard v3.0 — Detection Rules Engine
Mini-SIEM detection layer: 8 rules tagged to MITRE ATT&CK techniques.
Each rule fires a ThreatEventDB row, updates per-user risk score,
and auto-creates/updates AlertDB when triggered.

Pipeline: Collect → Normalize → Detect → Score → Respond
Architecture modelled on Wazuh / Microsoft Sentinel detection logic.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session

from database import (
    ActivityLogDB, AlertDB, ThreatEventDB, DevicePostureDB,
    VPNConnectionDB, SecurityScoreDB, UserDB
)

# ─────────────────────────────────────────────────────────────────
# MITRE ATT&CK Rule Definitions
# Each entry: (event_type, tactic, technique, severity, risk_delta, title, description_template)
# ─────────────────────────────────────────────────────────────────
RULES = {
    "brute_force": {
        "tactic":      "Credential Access",
        "technique":   "T1110",
        "severity":    "high",
        "risk_delta":  -30,
        "title":       "Brute Force Login Detected",
        "description": "≥5 failed login attempts in 10 minutes from {peer_ip}. Possible credential stuffing or password spray attack.",
    },
    "after_hours_access": {
        "tactic":      "Initial Access",
        "technique":   "T1078",
        "severity":    "medium",
        "risk_delta":  -10,
        "title":       "After-Hours Access Detected",
        "description": "Login at {hour}:00 UTC — outside normal business hours (06:00–22:00). User: {email}.",
    },
    "new_peer_ip": {
        "tactic":      "Initial Access",
        "technique":   "T1133",
        "severity":    "high",
        "risk_delta":  -25,
        "title":       "VPN Peer Connecting from New IP",
        "description": "Peer {email} previously connected from {old_ip}, now connecting from {new_ip}. Possible account takeover or travel.",
    },
    "failed_posture": {
        "tactic":      "Defense Evasion",
        "technique":   "T1562",
        "severity":    "high",
        "risk_delta":  -20,
        "title":       "Device Posture Check Failed",
        "description": "Device {device} failed posture check. Issues: {issues}. Access restricted until remediated.",
    },
    "large_download": {
        "tactic":      "Exfiltration",
        "technique":   "T1048",
        "severity":    "critical",
        "risk_delta":  -35,
        "title":       "Unusually Large Data Download",
        "description": "Peer {email} received {mb:.1f} MB — exceeds threshold of {threshold} MB. Possible data exfiltration.",
    },
    "malicious_dns": {
        "tactic":      "Command and Control",
        "technique":   "T1071.004",
        "severity":    "critical",
        "risk_delta":  -50,
        "title":       "DNS Hit on Malicious Domain",
        "description": "Peer {email} queried known-malicious domain '{domain}'. C2 communication or malware beacon suspected.",
    },
    "unusual_resource_access": {
        "tactic":      "Collection",
        "technique":   "T1078.002",
        "severity":    "medium",
        "risk_delta":  -10,
        "title":       "Unusual Resource Access Pattern",
        "description": "User {email} accessed resource '{resource}' not in their access history. Possible lateral movement or privilege abuse.",
    },
    "credential_tool": {
        "tactic":      "Credential Access",
        "technique":   "T1003",
        "severity":    "critical",
        "risk_delta":  -60,
        "title":       "Credential Dumping Tool Detected",
        "description": "Process '{process}' detected on endpoint of {email}. Immediate quarantine enforced.",
    },
}

# Threshold: if bytes_received exceeds this (MB), fire R5
LARGE_DOWNLOAD_THRESHOLD_MB = 500.0

# Known-malicious domains (demo set — in production, pull from a threat-intel feed)
MALICIOUS_DOMAINS = {
    "malware-c2.ru", "cobaltstrike-beacon.xyz", "darknet-exfil.onion.to",
    "phishing-kit.tk", "ransomware-panel.net", "botnet-ctrl.pw",
}


def _now():
    return datetime.now(timezone.utc)


def _fire_event(
    db: Session,
    rule_key: str,
    user_email: str,
    peer_ip: str = "",
    details: str = "",
    source: str = "system",
) -> ThreatEventDB:
    """Create a ThreatEventDB row, deduplicate within last 30 min, return the event."""
    rule = RULES[rule_key]
    cutoff = _now() - timedelta(minutes=30)

    # Dedup: don't re-fire the same rule for the same user within 30 min
    existing = (
        db.query(ThreatEventDB)
        .filter(
            ThreatEventDB.user_email == user_email,
            ThreatEventDB.event_type == rule_key,
            ThreatEventDB.created_at >= cutoff,
            ThreatEventDB.resolved == False,
        )
        .first()
    )
    if existing:
        return existing

    event = ThreatEventDB(
        user_email=user_email,
        peer_ip=peer_ip,
        event_type=rule_key,
        mitre_tactic=rule["tactic"],
        mitre_technique=rule["technique"],
        severity=rule["severity"],
        risk_delta=rule["risk_delta"],
        details=details or rule["description"],
        source=source,
    )
    db.add(event)
    return event


def _fire_alert(db: Session, rule_key: str, user_email: str, details: str = "") -> None:
    """Auto-create an AlertDB row for a detection rule if one isn't already open."""
    rule = RULES[rule_key]
    title = rule["title"]

    existing = (
        db.query(AlertDB)
        .filter(AlertDB.title.like(f"%{title}%"), AlertDB.status == "open")
        .first()
    )
    if existing:
        return

    db.add(AlertDB(
        title=f"{title} — {user_email}",
        severity=rule["severity"],
        category=rule["tactic"],
        status="open",
        description=details or rule["description"],
        source="Detection Engine",
        assignee="admin@company.com",
        ml_score=0.95,
        mitre_tactic=rule["tactic"],
        mitre_technique=rule["technique"],
    ))


def _quarantine_peer(db: Session, user_email: str) -> None:
    """Auto-quarantine VPN peer when a critical/high rule fires."""
    node = db.query(VPNConnectionDB).filter_by(user_email=user_email).first()
    if node and node.posture_status != "quarantine":
        node.posture_status = "quarantine"
        node.status = "disconnected"
        node.killswitch_active = True


def _deduct_org_score(db: Session, delta: int) -> None:
    """Deduct points from the global security score."""
    last = db.query(SecurityScoreDB).order_by(SecurityScoreDB.created_at.desc()).first()
    if last:
        new_val = max(200, last.score + delta)
        from helpers import grade
        db.add(SecurityScoreDB(score=new_val, grade=grade(new_val)))


# ─────────────────────────────────────────────────────────────────
# R1 — Brute Force (T1110)
# ─────────────────────────────────────────────────────────────────
def check_brute_force(db: Session, user_email: str, peer_ip: str = "") -> Optional[ThreatEventDB]:
    """Fire if ≥5 failed logins for this email in the last 10 minutes."""
    cutoff = _now() - timedelta(minutes=10)
    fails = (
        db.query(ActivityLogDB)
        .filter(
            ActivityLogDB.user_email == user_email,
            ActivityLogDB.action == "login_fail",
            ActivityLogDB.timestamp >= cutoff,
        )
        .count()
    )
    if fails >= 5:
        details = RULES["brute_force"]["description"].format(peer_ip=peer_ip or "unknown")
        event = _fire_event(db, "brute_force", user_email, peer_ip, details, source="app_logs")
        _fire_alert(db, "brute_force", user_email, details)
        _deduct_org_score(db, RULES["brute_force"]["risk_delta"])
        return event
    return None


# ─────────────────────────────────────────────────────────────────
# R2 — After-Hours Access (T1078)
# ─────────────────────────────────────────────────────────────────
def check_after_hours(db: Session, user_email: str, peer_ip: str = "") -> Optional[ThreatEventDB]:
    """Fire if the most recent login for this user was outside 06:00–22:00 UTC."""
    last_login = (
        db.query(ActivityLogDB)
        .filter(ActivityLogDB.user_email == user_email, ActivityLogDB.action == "login")
        .order_by(ActivityLogDB.timestamp.desc())
        .first()
    )
    if last_login:
        h = last_login.timestamp.hour
        if h < 6 or h >= 22:
            details = RULES["after_hours_access"]["description"].format(
                hour=h, email=user_email
            )
            event = _fire_event(db, "after_hours_access", user_email, peer_ip, details, source="app_logs")
            _fire_alert(db, "after_hours_access", user_email, details)
            _deduct_org_score(db, RULES["after_hours_access"]["risk_delta"])
            return event
    return None


# ─────────────────────────────────────────────────────────────────
# R3 — New Peer IP (T1133)
# ─────────────────────────────────────────────────────────────────
def check_new_peer_ip(db: Session, node: VPNConnectionDB) -> Optional[ThreatEventDB]:
    """Fire if a VPN peer connects from an IP different from their last known IP."""
    if not node.last_seen_ip or not node.endpoint_ip:
        return None
    if node.endpoint_ip != node.last_seen_ip:
        node.ip_changed = True
        details = RULES["new_peer_ip"]["description"].format(
            email=node.user_email,
            old_ip=node.last_seen_ip,
            new_ip=node.endpoint_ip,
        )
        event = _fire_event(db, "new_peer_ip", node.user_email, node.virtual_ip, details, source="vpn_gateway")
        _fire_alert(db, "new_peer_ip", node.user_email, details)
        _deduct_org_score(db, RULES["new_peer_ip"]["risk_delta"])
        return event
    return None


# ─────────────────────────────────────────────────────────────────
# R4 — Failed Posture Check (T1562)
# ─────────────────────────────────────────────────────────────────
def check_posture(
    db: Session,
    user_email: str,
    device_name: str,
    os_patched: bool,
    antivirus_on: bool,
    firewall_on: bool,
    disk_encrypted: bool,
    peer_ip: str = "",
    source: str = "agent",
) -> Optional[ThreatEventDB]:
    """Fire if any posture check fails; also compute posture score and risk level."""
    failures = []
    if not os_patched:       failures.append("OS unpatched")
    if not antivirus_on:     failures.append("Antivirus disabled")
    if not firewall_on:      failures.append("Firewall off")
    if not disk_encrypted:   failures.append("Disk not encrypted")

    # Compute score: each failure costs 25 points
    posture_score = max(0, 100 - len(failures) * 25)
    risk_level = (
        "critical" if posture_score <= 25 else
        "high"     if posture_score <= 50 else
        "medium"   if posture_score <= 75 else
        "low"
    )

    # Upsert DevicePostureDB record
    posture_row = (
        db.query(DevicePostureDB)
        .filter_by(user_email=user_email, device_name=device_name)
        .first()
    )
    if posture_row:
        posture_row.os_patched     = os_patched
        posture_row.antivirus_on   = antivirus_on
        posture_row.firewall_on    = firewall_on
        posture_row.disk_encrypted = disk_encrypted
        posture_row.posture_score  = posture_score
        posture_row.risk_level     = risk_level
        posture_row.source         = source
        posture_row.last_checked   = _now()
    else:
        db.add(DevicePostureDB(
            user_email=user_email,
            device_name=device_name,
            os_patched=os_patched,
            antivirus_on=antivirus_on,
            firewall_on=firewall_on,
            disk_encrypted=disk_encrypted,
            posture_score=posture_score,
            risk_level=risk_level,
            source=source,
        ))

    if failures:
        issue_str = ", ".join(failures)
        details = RULES["failed_posture"]["description"].format(
            device=device_name, issues=issue_str
        )
        event = _fire_event(db, "failed_posture", user_email, peer_ip, details, source=source)
        _fire_alert(db, "failed_posture", user_email, details)
        _quarantine_peer(db, user_email)
        _deduct_org_score(db, RULES["failed_posture"]["risk_delta"] * len(failures))
        return event
    return None


# ─────────────────────────────────────────────────────────────────
# R5 — Large Download (T1048)
# ─────────────────────────────────────────────────────────────────
def check_large_download(db: Session, node: VPNConnectionDB) -> Optional[ThreatEventDB]:
    """Fire if VPN bytes_received exceeds LARGE_DOWNLOAD_THRESHOLD_MB."""
    if (node.bytes_received or 0) >= LARGE_DOWNLOAD_THRESHOLD_MB:
        details = RULES["large_download"]["description"].format(
            email=node.user_email,
            mb=node.bytes_received,
            threshold=LARGE_DOWNLOAD_THRESHOLD_MB,
        )
        event = _fire_event(db, "large_download", node.user_email, node.virtual_ip, details, source="vpn_gateway")
        _fire_alert(db, "large_download", node.user_email, details)
        _deduct_org_score(db, RULES["large_download"]["risk_delta"])
        return event
    return None


# ─────────────────────────────────────────────────────────────────
# R6 — Malicious DNS (T1071.004)
# ─────────────────────────────────────────────────────────────────
def check_malicious_dns(db: Session, user_email: str, domain: str, peer_ip: str = "") -> Optional[ThreatEventDB]:
    """Fire if a queried domain matches the known-malicious blocklist."""
    domain_lower = domain.lower().strip()
    if domain_lower in MALICIOUS_DOMAINS:
        details = RULES["malicious_dns"]["description"].format(
            email=user_email, domain=domain_lower
        )
        event = _fire_event(db, "malicious_dns", user_email, peer_ip, details, source="vpn_gateway")
        _fire_alert(db, "malicious_dns", user_email, details)
        _quarantine_peer(db, user_email)
        _deduct_org_score(db, RULES["malicious_dns"]["risk_delta"])
        return event
    return None


# ─────────────────────────────────────────────────────────────────
# R7 — Unusual Resource Access (T1078.002)
# ─────────────────────────────────────────────────────────────────
def check_unusual_access(db: Session, user_email: str, resource: str, peer_ip: str = "") -> Optional[ThreatEventDB]:
    """Fire if user accesses a resource they've never touched before (based on activity log)."""
    prior = (
        db.query(ActivityLogDB)
        .filter(
            ActivityLogDB.user_email == user_email,
            ActivityLogDB.page == resource,
        )
        .count()
    )
    if prior == 0:
        details = RULES["unusual_resource_access"]["description"].format(
            email=user_email, resource=resource
        )
        event = _fire_event(db, "unusual_resource_access", user_email, peer_ip, details, source="app_logs")
        _fire_alert(db, "unusual_resource_access", user_email, details)
        _deduct_org_score(db, RULES["unusual_resource_access"]["risk_delta"])
        return event
    return None


# ─────────────────────────────────────────────────────────────────
# R8 — Credential Tool (T1003)
# ─────────────────────────────────────────────────────────────────
CREDENTIAL_TOOLS = {
    "mimikatz", "hashcat", "pwdump", "lazagne", "procdump",
    "gsecdump", "wce.exe", "fgdump", "lsadump",
}

def check_credential_tool(db: Session, user_email: str, process_name: str, peer_ip: str = "") -> Optional[ThreatEventDB]:
    """Fire if a known credential-dumping tool is reported by the endpoint agent."""
    if process_name.lower().strip() in CREDENTIAL_TOOLS:
        details = RULES["credential_tool"]["description"].format(
            process=process_name, email=user_email
        )
        event = _fire_event(db, "credential_tool", user_email, peer_ip, details, source="endpoint_agent")
        _fire_alert(db, "credential_tool", user_email, details)
        _quarantine_peer(db, user_email)
        _deduct_org_score(db, RULES["credential_tool"]["risk_delta"])
        return event
    return None


# ─────────────────────────────────────────────────────────────────
# Per-User Risk Score
# ─────────────────────────────────────────────────────────────────
def compute_user_risk_score(db: Session, user_email: str) -> dict:
    """
    Compute a 0–100 risk score for a user based on open threat events.
    Lower is riskier.  Returns score + contributing events + risk level.
    """
    cutoff = _now() - timedelta(days=7)
    open_events = (
        db.query(ThreatEventDB)
        .filter(
            ThreatEventDB.user_email == user_email,
            ThreatEventDB.resolved == False,
            ThreatEventDB.created_at >= cutoff,
        )
        .all()
    )
    total_delta = sum(abs(e.risk_delta) for e in open_events)
    score = max(0, 100 - total_delta)
    risk_level = (
        "critical" if score <= 20 else
        "high"     if score <= 40 else
        "medium"   if score <= 65 else
        "low"
    )
    return {
        "user_email": user_email,
        "risk_score": score,
        "risk_level": risk_level,
        "open_events": len(open_events),
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "mitre_technique": e.mitre_technique,
                "severity": e.severity,
                "risk_delta": e.risk_delta,
                "created_at": e.created_at.isoformat(),
            }
            for e in open_events
        ],
    }
