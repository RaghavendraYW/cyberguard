"""
CyberGuard v2.0 — Pydantic Schemas
All request/response validation models with field length constraints.
"""
import re
from typing import Optional, List
from pydantic import BaseModel, field_validator, EmailStr


# ── Validators ────────────────────────────────────────────────
def _require_strong_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"\d", v):
        raise ValueError("Password must contain at least one digit")
    return v


# ── Auth ──────────────────────────────────────────────────────
class LoginReq(BaseModel):
    email:    str
    password: str


class RefreshReq(BaseModel):
    refresh_token: str


class PasswordChangeReq(BaseModel):
    current_password: str
    new_password:     str

    @field_validator("new_password")
    @classmethod
    def password_strong(cls, v):
        return _require_strong_password(v)


# ── Tracking & ML ─────────────────────────────────────────────
class TrackReq(BaseModel):
    action:    str
    page:      str = ""
    userAgent: str = ""
    meta:      dict = {}


class SimulateReq(BaseModel):
    type: str = "brute_force"


class ClassifyReq(BaseModel):
    text: str


# ── Scan ─────────────────────────────────────────────────────
class ScanReq(BaseModel):
    domain: str


# ── Reports ──────────────────────────────────────────────────
class ReportGenReq(BaseModel):
    type: str = "security-posture"


# ── Users (Admin) ─────────────────────────────────────────────
class CreateUserReq(BaseModel):
    name:    str
    email:   str
    password: str
    role:    str = "Analyst"
    isAdmin: bool = False
    company: str = "Acme Corp"

    @field_validator("name")
    @classmethod
    def name_len(cls, v):
        if len(v.strip()) < 2:
            raise ValueError("Name must be at least 2 characters")
        return v.strip()

    @field_validator("password")
    @classmethod
    def password_strong(cls, v):
        return _require_strong_password(v)


class UpdateUserReq(BaseModel):
    isAdmin:  Optional[bool] = None
    role:     Optional[str] = None
    name:     Optional[str] = None
    password: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_strong(cls, v):
        if v:
            return _require_strong_password(v)
        return v


class ProfileUpdate(BaseModel):
    name:     Optional[str] = None
    role:     Optional[str] = None
    company:  Optional[str] = None
    domain:   Optional[str] = None
    password: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_strong(cls, v):
        if v:
            return _require_strong_password(v)
        return v


# ── Monitoring (legacy — kept for backwards compat) ──────────
class ActivityTelemetryReq(BaseModel):
    """Deprecated: replaced by SecurityEventReq in threat_detection routes."""
    tracking_key:  str
    active_window: str = ""   # Ignored — kept so old agents don't get a 422
    status:        str = "active"


# ── Threat Detection ──────────────────────────────────────────
class SecurityEventReq(BaseModel):
    tracking_key: str
    event_type:   str   # process_start | login_fail | large_download | credential_tool | dns_query
    process_name: Optional[str] = None
    domain:       Optional[str] = None
    severity:     Optional[str] = "medium"
    details:      Optional[str] = None
    posture:      Optional[dict] = None


class PostureReportReq(BaseModel):
    tracking_key:   str
    device_name:    str  = "Unknown Device"
    os_patched:     bool = True
    antivirus_on:   bool = True
    firewall_on:    bool = True
    disk_encrypted: bool = True


# ── Vendors ───────────────────────────────────────────────────
class VendorCreate(BaseModel):
    name:        str
    domain:      str
    category:    str = "SaaS"
    criticality: str = "Medium"
    score:       Optional[int] = None
    issues:      Optional[int] = None
    status:      str = "monitored"
    contact:     str = ""
    notes:       str = ""
    sla_days:    int = 90

    @field_validator("name")
    @classmethod
    def name_len(cls, v):
        if not v.strip():
            raise ValueError("Vendor name is required")
        return v.strip()[:120]

    @field_validator("domain")
    @classmethod
    def domain_len(cls, v):
        if not v.strip():
            raise ValueError("Domain is required")
        return v.strip()[:200]


class VendorUpdate(BaseModel):
    name:        Optional[str] = None
    domain:      Optional[str] = None
    category:    Optional[str] = None
    criticality: Optional[str] = None
    score:       Optional[int] = None
    issues:      Optional[int] = None
    status:      Optional[str] = None
    contact:     Optional[str] = None
    notes:       Optional[str] = None
    sla_days:    Optional[int] = None


# ── Alerts ────────────────────────────────────────────────────
class AlertCreate(BaseModel):
    title:       str
    severity:    str = "medium"
    category:    str = "General"
    description: str = ""
    source:      str = "manual"
    assignee:    str = ""

    @field_validator("title")
    @classmethod
    def title_len(cls, v):
        if not v.strip():
            raise ValueError("Alert title is required")
        return v.strip()[:300]


class AlertUpdate(BaseModel):
    title:           Optional[str] = None
    severity:        Optional[str] = None
    category:        Optional[str] = None
    status:          Optional[str] = None
    description:     Optional[str] = None
    assignee:        Optional[str] = None
    mitre_tactic:    Optional[str] = None
    mitre_technique: Optional[str] = None

# ── Leaks ─────────────────────────────────────────────────────
class LeakCreate(BaseModel):
    title:       str
    severity:    str = "high"
    source:      str = "Dark Web"
    credentials: int = 0
    records:     int = 0
    details:     str = ""

    @field_validator("title")
    @classmethod
    def title_len(cls, v):
        if not v.strip():
            raise ValueError("Leak title is required")
        return v.strip()[:300]


class LeakUpdate(BaseModel):
    status:      Optional[str] = None
    severity:    Optional[str] = None
    credentials: Optional[int] = None
    records:     Optional[int] = None
    details:     Optional[str] = None


# ── Questionnaires ────────────────────────────────────────────
class QCreate(BaseModel):
    title:     str
    framework: str = "Custom"
    vendor:    str = ""
    total:     int = 20
    due:       str = ""
    notes:     str = ""


class QUpdate(BaseModel):
    answered:  Optional[int] = None
    status:    Optional[str] = None
    title:     Optional[str] = None
    framework: Optional[str] = None
    vendor:    Optional[str] = None
    total:     Optional[int] = None
    due_date:  Optional[str] = None
    notes:     Optional[str] = None


# ── Preferences ───────────────────────────────────────────────
class PreferencesUpdate(BaseModel):
    notif_critical:    Optional[bool] = None
    notif_leaks:       Optional[bool] = None
    notif_ml:          Optional[bool] = None
    ml_autotrain:      Optional[bool] = None
    ml_vendorscan:     Optional[bool] = None
    anomaly_threshold: Optional[float] = None
    theme:             Optional[str] = None

    @field_validator("anomaly_threshold")
    @classmethod
    def threshold_range(cls, v):
        if v is not None and not (0.1 <= v <= 0.99):
            raise ValueError("Threshold must be between 0.1 and 0.99")
        return v


# ── Webhooks ─────────────────────────────────────────────────
class WebhookConfigReq(BaseModel):
    name:      str = "Default"
    url:       str
    secret:    str = ""
    events:    str = "critical_alert,new_leak"
    is_active: bool = True

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v):
        if not v.strip().startswith("http"):
            raise ValueError("URL must start with http:// or https://")
        return v.strip()[:500]
