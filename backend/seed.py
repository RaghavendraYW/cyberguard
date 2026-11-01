"""
CyberGuard v3.0 — Database Seed
Idempotent initial data population — safe to run on every startup.
Only inserts data if the database is empty (first run / fresh deployment).
Includes seeded ThreatEventDB scenarios (all 8 MITRE rules) and DevicePostureDB records.
"""
import random
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash

from database import (
    UserDB, VendorDB, AlertDB, LeakDB, QuestionnaireDB,
    ActivityLogDB, SecurityScoreDB, VPNConnectionDB,
    ThreatEventDB, DevicePostureDB
)
from helpers import grade


def _now():
    return datetime.now(timezone.utc)


def seed_vpn(db):
    """Seed initial VPN node connections and zero-trust postures."""
    if db.query(VPNConnectionDB).first():
        return
    vpn_nodes = [
        dict(
            user_name="Alex Kumar",
            user_email="admin@company.com",
            device_name="MacBook-Pro-M2-Alex",
            protocol="WireGuard",
            virtual_ip="10.8.0.2",
            endpoint_ip="198.51.100.44",
            server_location="US-East (Virginia Primary)",
            status="connected",
            bytes_sent=1420.5,
            bytes_received=3890.2,
            latency_ms=16,
            posture_status="compliant",
            killswitch_active=True,
        ),
        dict(
            user_name="Priya Sharma",
            user_email="priya@company.com",
            device_name="ThinkPad-X1-Priya",
            protocol="WireGuard",
            virtual_ip="10.8.0.3",
            endpoint_ip="203.0.113.88",
            server_location="AP-South (Mumbai Hub)",
            status="connected",
            bytes_sent=840.1,
            bytes_received=2110.7,
            latency_ms=28,
            posture_status="compliant",
            killswitch_active=True,
        ),
        dict(
            user_name="Rahul Verma",
            user_email="rahul@company.com",
            device_name="Ubuntu-DevOps-Workstation",
            protocol="WireGuard",
            virtual_ip="10.8.0.4",
            endpoint_ip="198.51.100.122",
            server_location="US-East (Virginia Primary)",
            status="connected",
            bytes_sent=4320.0,
            bytes_received=9180.4,
            latency_ms=19,
            posture_status="compliant",
            killswitch_active=True,
        ),
        dict(
            user_name="Sara Khan",
            user_email="sara@company.com",
            device_name="Dell-Precision-Sara",
            protocol="WireGuard",
            virtual_ip="10.8.0.5",
            endpoint_ip="192.0.2.14",
            server_location="EU-Central (Frankfurt)",
            status="connected",
            bytes_sent=620.3,
            bytes_received=1240.8,
            latency_ms=34,
            posture_status="compliant",
            killswitch_active=True,
        ),
        dict(
            user_name="James Wilson",
            user_email="james@company.com",
            device_name="Galaxy-Book-James",
            protocol="WireGuard",
            virtual_ip="10.8.0.6",
            endpoint_ip="198.51.100.201",
            server_location="US-East (Virginia Primary)",
            status="connected",
            bytes_sent=310.4,
            bytes_received=890.1,
            latency_ms=22,
            posture_status="compliant",
            killswitch_active=True,
        ),
        dict(
            user_name="Unrecognized BYOD",
            user_email="contractor@external.org",
            device_name="Win10-Unmanaged-BYOD",
            protocol="OpenVPN",
            virtual_ip="10.8.0.19",
            endpoint_ip="45.33.32.156",
            server_location="US-East (Virginia Primary)",
            status="disconnected",
            bytes_sent=45.2,
            bytes_received=112.0,
            latency_ms=120,
            posture_status="quarantine",
            killswitch_active=False,
        )
    ]
    for node in vpn_nodes:
        db.add(VPNConnectionDB(**node))
    db.commit()


def seed_threat_events(db):
    """Seed one example of each of the 8 MITRE-tagged detection rules (all marked source='simulated')."""
    if db.query(ThreatEventDB).first():
        return

    now = datetime.now(timezone.utc)
    events = [
        # R1 — Brute Force (T1110)
        dict(
            user_email="priya@company.com", peer_ip="10.8.0.3",
            event_type="brute_force", mitre_tactic="Credential Access",
            mitre_technique="T1110", severity="high", risk_delta=-30,
            details="7 failed login attempts in 8 minutes from 203.0.113.88. Possible credential spray.",
            source="simulated", resolved=False,
            created_at=now - timedelta(hours=2),
        ),
        # R2 — After-Hours Access (T1078)
        dict(
            user_email="rahul@company.com", peer_ip="10.8.0.4",
            event_type="after_hours_access", mitre_tactic="Initial Access",
            mitre_technique="T1078", severity="medium", risk_delta=-10,
            details="Login at 03:14 UTC — outside business hours (06:00–22:00). User: rahul@company.com.",
            source="simulated", resolved=False,
            created_at=now - timedelta(hours=18),
        ),
        # R3 — New Peer IP (T1133)
        dict(
            user_email="sara@company.com", peer_ip="10.8.0.5",
            event_type="new_peer_ip", mitre_tactic="Initial Access",
            mitre_technique="T1133", severity="high", risk_delta=-25,
            details="Peer sara@company.com previously from 192.0.2.14, now from 45.33.32.100. Possible account takeover.",
            source="simulated", resolved=False,
            created_at=now - timedelta(hours=6),
        ),
        # R4 — Failed Posture (T1562)
        dict(
            user_email="james@company.com", peer_ip="10.8.0.6",
            event_type="failed_posture", mitre_tactic="Defense Evasion",
            mitre_technique="T1562", severity="high", risk_delta=-20,
            details="Galaxy-Book-James failed posture: OS unpatched, Firewall off. Access restricted.",
            source="simulated", resolved=False,
            created_at=now - timedelta(hours=4),
        ),
        # R5 — Large Download (T1048)
        dict(
            user_email="rahul@company.com", peer_ip="10.8.0.4",
            event_type="large_download", mitre_tactic="Exfiltration",
            mitre_technique="T1048", severity="critical", risk_delta=-35,
            details="Peer rahul@company.com received 9,180.4 MB — exceeds 500 MB threshold. Possible data exfiltration.",
            source="simulated", resolved=False,
            created_at=now - timedelta(hours=1),
        ),
        # R6 — Malicious DNS (T1071.004)
        dict(
            user_email="contractor@external.org", peer_ip="10.8.0.19",
            event_type="malicious_dns", mitre_tactic="Command and Control",
            mitre_technique="T1071.004", severity="critical", risk_delta=-50,
            details="Peer queried 'cobaltstrike-beacon.xyz'. C2 beacon suspected. Peer quarantined.",
            source="simulated", resolved=False,
            created_at=now - timedelta(hours=3),
        ),
        # R7 — Unusual Resource Access (T1078.002)
        dict(
            user_email="priya@company.com", peer_ip="10.8.0.3",
            event_type="unusual_resource_access", mitre_tactic="Collection",
            mitre_technique="T1078.002", severity="medium", risk_delta=-10,
            details="User priya@company.com accessed /api/admin/users — not in her access history.",
            source="simulated", resolved=False,
            created_at=now - timedelta(hours=10),
        ),
        # R8 — Credential Tool (T1003)
        dict(
            user_email="james@company.com", peer_ip="10.8.0.6",
            event_type="credential_tool", mitre_tactic="Credential Access",
            mitre_technique="T1003", severity="critical", risk_delta=-60,
            details="Process 'mimikatz.exe' detected on Galaxy-Book-James. Immediate quarantine enforced.",
            source="simulated", resolved=False,
            created_at=now - timedelta(minutes=30),
        ),
        # R1 resolved — example triaged event
        dict(
            user_email="priya@company.com", peer_ip="10.8.0.3",
            event_type="brute_force", mitre_tactic="Credential Access",
            mitre_technique="T1110", severity="high", risk_delta=-30,
            details="(Resolved) Brute force from locked-out user. Confirmed legitimate via MFA.",
            source="simulated", resolved=True,
            created_at=now - timedelta(days=2),
        ),
    ]
    for e in events:
        db.add(ThreatEventDB(**e))
    db.commit()


def seed_device_posture(db):
    """Seed device posture: compliant, failing, and critical device states."""
    if db.query(DevicePostureDB).first():
        return

    now = datetime.now(timezone.utc)
    records = [
        dict(
            user_email="admin@company.com",  device_name="MacBook-Pro-M2-Alex",
            os_patched=True, antivirus_on=True, firewall_on=True, disk_encrypted=True,
            posture_score=100, risk_level="low", source="simulated",
            last_checked=now - timedelta(hours=1),
        ),
        dict(
            user_email="priya@company.com", device_name="ThinkPad-X1-Priya",
            os_patched=True, antivirus_on=True, firewall_on=True, disk_encrypted=True,
            posture_score=100, risk_level="low", source="simulated",
            last_checked=now - timedelta(hours=2),
        ),
        dict(
            user_email="rahul@company.com", device_name="Ubuntu-DevOps-Workstation",
            os_patched=True, antivirus_on=True, firewall_on=True, disk_encrypted=True,
            posture_score=100, risk_level="low", source="simulated",
            last_checked=now - timedelta(hours=3),
        ),
        dict(  # Failing: OS unpatched + firewall off
            user_email="james@company.com", device_name="Galaxy-Book-James",
            os_patched=False, antivirus_on=True, firewall_on=False, disk_encrypted=True,
            posture_score=50, risk_level="high", source="simulated",
            last_checked=now - timedelta(hours=4),
        ),
        dict(  # Critical: all checks failing
            user_email="contractor@external.org", device_name="Win10-Unmanaged-BYOD",
            os_patched=False, antivirus_on=False, firewall_on=False, disk_encrypted=False,
            posture_score=0, risk_level="critical", source="simulated",
            last_checked=now - timedelta(hours=5),
        ),
    ]
    for r in records:
        db.add(DevicePostureDB(**r))
    db.commit()


def seed_db(db):
    # Ensure VPN nodes and threat data are seeded even if users already exist
    seed_vpn(db)
    seed_threat_events(db)
    seed_device_posture(db)

    # ── Idempotency guard: skip rest if users exist ────────
    if db.query(UserDB).first():
        return   # Database already seeded — do nothing

    print("\U0001f331 Seeding fresh database…")

    # ── Users ─────────────────────────────────────────────────
    for u_data in [
        dict(name="Alex Kumar",   email="admin@company.com", password_hash=generate_password_hash("Admin@1234"),    role="CISO",             is_admin=True),
        dict(name="Priya Sharma", email="priya@company.com", password_hash=generate_password_hash("Analyst@1234"), role="Security Analyst",  is_admin=False),
        dict(name="Rahul Verma",  email="rahul@company.com", password_hash=generate_password_hash("Devops@1234"),  role="DevOps Engineer",   is_admin=False),
        dict(name="Sara Khan",    email="sara@company.com",  password_hash=generate_password_hash("SecEng@1234"),  role="Security Engineer", is_admin=False),
        dict(name="James Wilson", email="james@company.com", password_hash=generate_password_hash("NetAdm@1234"),  role="Network Admin",     is_admin=False),
    ]:
        db.add(UserDB(**u_data))

    # ── Vendors ───────────────────────────────────────────────
    for v in [
        dict(name="Salesforce",   domain="salesforce.com",  category="CRM",                 criticality="Critical", score=880, issues=2,  status="monitored", trend="+5",  sla_days=90),
        dict(name="AWS",          domain="aws.amazon.com",  category="Cloud Infrastructure", criticality="Critical", score=912, issues=1,  status="monitored", trend="+2",  sla_days=90),
        dict(name="CloudHostPro", domain="cloudhostpro.io", category="Cloud Infrastructure", criticality="High",     score=540, issues=18, status="review",    trend="-42", sla_days=30),
        dict(name="Slack",        domain="slack.com",       category="Communication",        criticality="High",     score=820, issues=5,  status="monitored", trend="-8",  sla_days=90),
        dict(name="Stripe",       domain="stripe.com",      category="Payment Processing",   criticality="Critical", score=930, issues=1,  status="monitored", trend="+7",  sla_days=60),
        dict(name="Zoom",         domain="zoom.us",         category="Communication",        criticality="Medium",   score=690, issues=11, status="review",    trend="-15", sla_days=90),
    ]:
        db.add(VendorDB(**v))

    # ── Alerts ────────────────────────────────────────────────
    for a in [
        dict(title="SSL Certificate expiring in 7 days",    severity="critical", category="Website Security", status="open",         description="api.acmecorp.com SSL cert expires soon."),
        dict(title="Admin panel exposed to public internet", severity="critical", category="Network",          status="open",         description="admin.acmecorp.com is publicly accessible."),
        dict(title="Vendor score dropped 42 points",        severity="high",     category="Vendor Risk",       status="open",         description="CloudHostPro score dropped significantly."),
        dict(title="DMARC policy not enforced",             severity="high",     category="Email Security",    status="acknowledged", description="DMARC policy is in p=none mode."),
        dict(title="New credential leak detected",          severity="critical", category="Data Leak",         status="open",         description="2 employee credentials found on dark web."),
    ]:
        db.add(AlertDB(**a))

    # ── Leaks ─────────────────────────────────────────────────
    for l in [
        dict(title="Corporate credentials on BreachForums", severity="critical", source="Dark Web",   credentials=2, records=0, status="investigating", details="Employee credentials found in breach dump."),
        dict(title="API keys found on Pastebin",            severity="high",     source="Paste Site", credentials=0, records=0, status="open",          details="Internal API keys exposed publicly."),
    ]:
        db.add(LeakDB(**l))

    # ── Questionnaires ────────────────────────────────────────
    for q in [
        dict(title="SOC 2 Type II Assessment", framework="SOC 2",     vendor="CloudHostPro", total=21, answered=15, status="in_progress", due_date="2026-04-20"),
        dict(title="GDPR Compliance Review",   framework="GDPR",      vendor="",             total=11, answered=11, status="completed",   due_date="2026-02-28"),
        dict(title="ISO 27001 Gap Analysis",   framework="ISO 27001", vendor="AWS",          total=30, answered=8,  status="in_progress", due_date="2026-05-15"),
        dict(title="NIST CSF Assessment",      framework="NIST CSF",  vendor="",             total=23, answered=14, status="in_progress", due_date="2026-06-01"),
        dict(title="PCI DSS v4.0 Audit",       framework="PCI DSS",   vendor="Stripe",       total=15, answered=6,  status="in_progress", due_date="2026-05-30"),
        dict(title="HIPAA Security Review",    framework="HIPAA",     vendor="",             total=18, answered=12, status="in_progress", due_date="2026-07-01"),
    ]:
        db.add(QuestionnaireDB(**q))

    # ── Score history (30 days) ───────────────────────────────
    base = 742
    for days_ago in range(29, -1, -1):
        s = max(100, min(950, base + random.randint(-15, 15)))
        ts = _now() - timedelta(days=days_ago)
        db.add(SecurityScoreDB(score=s, grade=grade(s), created_at=ts))
        base = s

    # ── Activity logs (300 entries over last 30 days) ─────────
    users_emails = ["admin@company.com", "priya@company.com", "rahul@company.com", "sara@company.com", "james@company.com"]
    acts = ["login", "view_dashboard", "export_report", "add_vendor", "scan_domain", "access_settings", "view_vendor", "update_alert", "delete_alert", "download_report"]
    devices = ["Windows PC", "MacBook", "Linux", "Windows PC", "Windows PC"]
    for i in range(300):
        hour = random.randint(8, 20) if random.random() > 0.05 else random.randint(1, 5)
        ts = _now() - timedelta(days=random.randint(0, 30))
        ts = ts.replace(hour=hour, minute=random.randint(0, 59))
        uidx = random.randint(0, 4)
        db.add(ActivityLogDB(
            user_email=users_emails[uidx], action=random.choice(acts),
            ip_address=f"192.168.1.{random.randint(1, 80)}", device_info=devices[uidx],
            timestamp=ts, is_anomaly=(hour < 6),
            anomaly_score=(0.92 if hour < 6 else round(random.uniform(0.1, 0.4), 2))
        ))

    db.commit()
    print("✅ Database seeded: 5 users, 6 vendors, 5 alerts, 2 leaks, 6 questionnaires, 30-day score history, 300 activity logs")
