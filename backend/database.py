"""
CyberGuard v2.0 — Database Models & Session
SQLAlchemy engine, session factory, and all ORM model classes.
"""
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DATABASE_URL

from sqlalchemy import engine as sa_engine, event

# ── Engine & Session ──────────────────────────────────────────
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 15})
    
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
else:
    engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)

DBSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_db():
    db = DBSession()
    try:
        yield db
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
    last_seen     = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))


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
    created_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AlertDB(Base):
    __tablename__ = "alerts"
    id          = Column(Integer, primary_key=True)
    title       = Column(String(300))
    severity    = Column(String(20), default="medium")
    category    = Column(String(100), default="General")
    status      = Column(String(30), default="open")
    description = Column(Text, default="")
    source      = Column(String(50), default="manual")
    ml_score    = Column(Float, default=0.0)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))


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
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))


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
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ActivityLogDB(Base):
    __tablename__ = "activity_logs"
    id            = Column(Integer, primary_key=True)
    user_email    = Column(String(180))
    action        = Column(String(100))
    ip_address    = Column(String(50), default="")
    user_agent    = Column(String(300), default="")
    device_info   = Column(String(100), default="")
    page          = Column(String(100), default="")
    timestamp     = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_anomaly    = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)


class SecurityScoreDB(Base):
    __tablename__ = "security_scores"
    id         = Column(Integer, primary_key=True)
    score      = Column(Integer)
    grade      = Column(String(5), default="B")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ReportDB(Base):
    __tablename__ = "reports"
    id         = Column(Integer, primary_key=True)
    title      = Column(String(300))
    type       = Column(String(50), default="security-posture")
    pages      = Column(Integer, default=5)
    content    = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class EmployeeActivityDB(Base):
    __tablename__ = "employee_activity"
    id            = Column(Integer, primary_key=True)
    user_id       = Column(Integer)
    active_window = Column(String(300), default="")
    device_ip     = Column(String(50), default="")
    status        = Column(String(20), default="active")
    timestamp     = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Create all tables
Base.metadata.create_all(bind=engine)
