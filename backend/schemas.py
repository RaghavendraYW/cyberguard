"""
CyberGuard v2.0 — Pydantic Schemas
All request/response models.
"""
from typing import Optional
from pydantic import BaseModel


class LoginReq(BaseModel):
    email: str
    password: str


class TrackReq(BaseModel):
    action: str
    page: str = ""
    userAgent: str = ""
    meta: dict = {}


class SimulateReq(BaseModel):
    type: str = "brute_force"


class ClassifyReq(BaseModel):
    text: str


class ScanReq(BaseModel):
    domain: str


class ReportGenReq(BaseModel):
    type: str = "security-posture"


class CreateUserReq(BaseModel):
    name: str
    email: str
    password: str
    role: str = "Analyst"
    isAdmin: bool = False
    company: str = "Acme Corp"


class UpdateUserReq(BaseModel):
    isAdmin: Optional[bool] = None
    role: Optional[str] = None
    name: Optional[str] = None
    password: Optional[str] = None


class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    domain: Optional[str] = None
    password: Optional[str] = None


class ActivityTelemetryReq(BaseModel):
    tracking_key: str
    active_window: str
    status: str = "active"


class EmployeeActivityRes(BaseModel):
    id: int
    user_id: int
    user_name: str
    user_email: str
    active_window: str
    status: str
    timestamp: str


class VendorCreate(BaseModel):
    name: str
    domain: str
    category: str = "SaaS"
    criticality: str = "Medium"
    score: Optional[int] = None
    issues: Optional[int] = None
    status: str = "monitored"
    contact: str = ""
    notes: str = ""


class VendorUpdate(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    category: Optional[str] = None
    criticality: Optional[str] = None
    score: Optional[int] = None
    issues: Optional[int] = None
    status: Optional[str] = None
    contact: Optional[str] = None
    notes: Optional[str] = None


class AlertCreate(BaseModel):
    title: str
    severity: str = "medium"
    category: str = "General"
    description: str = ""
    source: str = "manual"


class AlertUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None


class LeakCreate(BaseModel):
    title: str
    severity: str = "high"
    source: str = "Dark Web"
    credentials: int = 0
    records: int = 0
    details: str = ""


class LeakUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    credentials: Optional[int] = None
    records: Optional[int] = None
    details: Optional[str] = None


class QCreate(BaseModel):
    title: str
    framework: str = "Custom"
    vendor: str = ""
    total: int = 20
    due: str = ""
    notes: str = ""


class QUpdate(BaseModel):
    answered: Optional[int] = None
    status: Optional[str] = None
    title: Optional[str] = None
    framework: Optional[str] = None
    vendor: Optional[str] = None
    total: Optional[int] = None
    due_date: Optional[str] = None
    notes: Optional[str] = None
