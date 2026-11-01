"""
CyberGuard v3.0 — Database Models & Session
SQLAlchemy engine, session factory, and all ORM model classes.
Includes: ThreatEventDB (MITRE-tagged events), DevicePostureDB (fleet posture),
          enhanced AlertDB (MITRE technique), VPNConnectionDB (IP-change tracking).
"""
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime, event
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DATABASE_URL

# ── Engine & Session ──────────────────────────────────────────
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 15})

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=300,
        connect_args={
            "connect_timeout": 10,
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5
        }
    )

DBSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def _now():
    return datetime.now(timezone.utc)


def get_db():
    db = DBSession()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()



# ══════════════════════════════════════════════════════════════
# DATABASE MODELS
# ══════════════════════════════════════════════════════════════
class UserDB(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True)
    name          = Column(String(120), nullable=False)
    email         = Column(String(180), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role          = Column(String(80), default="Analyst")
    is_admin      = Column(Boolean, default=False)
    company       = Column(String(120), default="Acme Corp")
    domain        = Column(String(120), default="")
    tracking_key  = Column(String(120), unique=True, nullable=True)
    totp_secret   = Column(String(64), nullable=True)
    totp_enabled  = Column(Boolean, default=False)
    vpn_authorized = Column(Boolean, default=False)
    last_seen     = Column(DateTime, default=_now)
    created_at    = Column(DateTime, default=_now)


class UserPreferencesDB(Base):
    """Stores per-user UI/notification preferences."""
    __tablename__ = "user_preferences"
    id              = Column(Integer, primary_key=True)
    user_id         = Column(Integer, nullable=False, unique=True)
    notif_critical  = Column(Boolean, default=True)
    notif_leaks     = Column(Boolean, default=True)
    notif_ml        = Column(Boolean, default=True)
    ml_autotrain    = Column(Boolean, default=True)
    ml_vendorscan   = Column(Boolean, default=True)
    anomaly_threshold = Column(Float, default=0.7)
    theme           = Column(String(10), default="dark")
    updated_at      = Column(DateTime, default=_now, onupdate=_now)


class VendorDB(Base):
    __tablename__ = "vendors"
    id           = Column(Integer, primary_key=True)
    name         = Column(String(120))
    domain       = Column(String(200))
    category     = Column(String(80), default="SaaS")
    criticality  = Column(String(20), default="Medium")
    score        = Column(Integer, default=700)
    issues       = Column(Integer, default=0)
    status       = Column(String(30), default="monitored")
    contact      = Column(String(200), default="")
    notes        = Column(Text, default="")
    trend        = Column(String(10), default="+0")
    last_scanned = Column(String(50), default="Never")
    # SLA tracking
    sla_days     = Column(Integer, default=90)    # review SLA in days
    last_review  = Column(DateTime, nullable=True)
    next_review  = Column(DateTime, nullable=True)
    created_at   = Column(DateTime, default=_now)


class AlertDB(Base):
    __tablename__ = "alerts"
    id               = Column(Integer, primary_key=True)
    title            = Column(String(300))
    severity         = Column(String(20), default="medium")
    category         = Column(String(100), default="General")
    status           = Column(String(30), default="open")
    description      = Column(Text, default="")
    source           = Column(String(50), default="manual")
    assignee         = Column(String(180), default="")    # email of assigned analyst
    ml_score         = Column(Float, default=0.0)
    mitre_tactic     = Column(String(80), default="")     # e.g. "Credential Access"
    mitre_technique  = Column(String(30), default="")     # e.g. "T1110"
    created_at       = Column(DateTime, default=_now)
    updated_at       = Column(DateTime, default=_now, onupdate=_now)


class LeakDB(Base):
    __tablename__ = "data_leaks"
    id          = Column(Integer, primary_key=True)
    title       = Column(String(300))
    severity    = Column(String(20), default="high")
    source      = Column(String(100), default="Dark Web")
    credentials = Column(Integer, default=0)
    records     = Column(Integer, default=0)
    status      = Column(String(30), default="open")
    details     = Column(Text, default="")
    created_at  = Column(DateTime, default=_now)


class QuestionnaireDB(Base):
    __tablename__ = "questionnaires"
    id         = Column(Integer, primary_key=True)
    title      = Column(String(300))
    framework  = Column(String(50), default="Custom")
    vendor     = Column(String(120), default="")
    total      = Column(Integer, default=20)
    answered   = Column(Integer, default=0)
    status     = Column(String(30), default="pending")
    due_date   = Column(String(20), default="")
    notes      = Column(Text, default="")
    created_at = Column(DateTime, default=_now)


class ActivityLogDB(Base):
    __tablename__ = "activity_logs"
    id            = Column(Integer, primary_key=True)
    user_email    = Column(String(180))
    action        = Column(String(100))
    ip_address    = Column(String(50), default="")
    user_agent    = Column(String(300), default="")
    device_info   = Column(String(100), default="")
    page          = Column(String(100), default="")
    timestamp     = Column(DateTime, default=_now)
    is_anomaly    = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)


class SecurityScoreDB(Base):
    __tablename__ = "security_scores"
    id         = Column(Integer, primary_key=True)
    score      = Column(Integer)
    grade      = Column(String(5), default="B")
    created_at = Column(DateTime, default=_now)


class ReportDB(Base):
    __tablename__ = "reports"
    id         = Column(Integer, primary_key=True)
    title      = Column(String(300))
    type       = Column(String(50), default="security-posture")
    pages      = Column(Integer, default=5)
    content    = Column(Text, default="")
    created_at = Column(DateTime, default=_now)


class EmployeeActivityDB(Base):
    __tablename__ = "employee_activity"
    id            = Column(Integer, primary_key=True)
    user_id       = Column(Integer)
    active_window = Column(String(300), default="")
    device_ip     = Column(String(50), default="")
    status        = Column(String(20), default="active")
    timestamp     = Column(DateTime, default=_now)


class WebhookConfigDB(Base):
    """Stores org-level webhook delivery configs."""
    __tablename__ = "webhook_configs"
    id          = Column(Integer, primary_key=True)
    name        = Column(String(120), default="Default")
    url         = Column(String(500))
    secret      = Column(String(200), default="")
    events      = Column(String(300), default="critical_alert,new_leak")  # comma-separated
    is_active   = Column(Boolean, default=True)
    created_at  = Column(DateTime, default=_now)


class RefreshTokenDB(Base):
    """Tracks issued refresh tokens for revocation support."""
    __tablename__ = "refresh_tokens"
    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, nullable=False)
    token_hash = Column(String(256), unique=True, nullable=False)
    created_at = Column(DateTime, default=_now)
    expires_at = Column(DateTime, nullable=False)
    revoked    = Column(Boolean, default=False)


class VPNConnectionDB(Base):
    """Tracks active and historical secure VPN tunnels and node telemetry."""
    __tablename__ = "vpn_connections"
    id                = Column(Integer, primary_key=True)
    user_name         = Column(String(120), default="Employee")
    user_email        = Column(String(180), nullable=False)
    device_name       = Column(String(120), default="Workstation")
    protocol          = Column(String(40), default="WireGuard")   # WireGuard, OpenVPN, IPsec
    virtual_ip        = Column(String(50), default="10.8.0.2")    # Assigned tunnel IP
    endpoint_ip       = Column(String(50), default="")            # Current public WAN IP
    last_seen_ip      = Column(String(50), default="")            # Previous IP — change triggers R3
    ip_changed        = Column(Boolean, default=False)            # R3: new peer IP detection flag
    server_location   = Column(String(100), default="US-East Gateway")
    status            = Column(String(30), default="connected")   # connected, disconnected, degraded
    bytes_sent        = Column(Float, default=0.0)                # MB
    bytes_received    = Column(Float, default=0.0)                # MB
    latency_ms        = Column(Integer, default=24)               # Handshake latency
    posture_status    = Column(String(30), default="compliant")   # compliant, non-compliant, quarantine
    killswitch_active = Column(Boolean, default=True)
    is_authenticated  = Column(Boolean, default=False)            # Zero-Trust MFA verified status
    auth_method       = Column(String(32), default="authenticator") # authenticator / pki / cert
    mfa_verified_at   = Column(DateTime, nullable=True)           # Timestamp of last successful TOTP check
    connected_at      = Column(DateTime, default=_now)
    last_handshake    = Column(DateTime, default=_now)


class ThreatEventDB(Base):
    """Normalized, MITRE ATT&CK-tagged security events from all collection sources."""
    __tablename__ = "threat_events"
    id               = Column(Integer, primary_key=True)
    user_email       = Column(String(180), default="")         # Subject of the event
    peer_ip          = Column(String(50), default="")          # VPN virtual IP at time of event
    event_type       = Column(String(80), nullable=False)      # brute_force | new_peer_ip | large_download | etc.
    mitre_tactic     = Column(String(80), default="")          # e.g. "Credential Access"
    mitre_technique  = Column(String(30), default="")          # e.g. "T1110"
    severity         = Column(String(20), default="medium")    # low | medium | high | critical
    risk_delta       = Column(Integer, default=0)              # Negative points deducted from user risk score
    details          = Column(Text, default="")
    source           = Column(String(50), default="system")    # vpn_gateway | app_logs | endpoint_agent | simulated
    resolved         = Column(Boolean, default=False)
    created_at       = Column(DateTime, default=_now)


class DevicePostureDB(Base):
    """Per-device security posture check results (patch, AV, firewall, encryption)."""
    __tablename__ = "device_posture"
    id              = Column(Integer, primary_key=True)
    user_email      = Column(String(180), nullable=False)
    device_name     = Column(String(120), default="Unknown Device")
    os_patched      = Column(Boolean, default=True)            # OS fully patched
    antivirus_on    = Column(Boolean, default=True)            # AV/EDR running
    firewall_on     = Column(Boolean, default=True)            # Host firewall active
    disk_encrypted  = Column(Boolean, default=True)            # Full-disk encryption
    posture_score   = Column(Integer, default=100)             # 0–100 composite score
    risk_level      = Column(String(20), default="low")        # low | medium | high | critical
    source          = Column(String(50), default="agent")      # agent | manual | simulated
    last_checked    = Column(DateTime, default=_now)


# Create all tables
Base.metadata.create_all(bind=engine)
