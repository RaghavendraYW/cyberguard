"""
CyberGuard v3.0 — Threat Detection & Posture API
Provides structured security event ingestion (replacing active-window surveillance),
device posture reporting, fleet health, per-user risk scores, and event triage.

Endpoints:
  POST /api/threats/ingest        — agent posts a security event (R1–R8)
  POST /api/threats/dns           — agent reports a DNS query (R6)
  GET  /api/threats/events        — list threat events (filterable)
  GET  /api/threats/risk-scores   — per-user risk scores for fleet view
  POST /api/threats/resolve/{id}  — mark an event resolved (SOC triage)
  POST /api/posture/report        — agent posts device posture check (R4)
  GET  /api/posture/fleet         — fleet-wide posture health grid
  GET  /api/posture/user/{email}  — single user posture detail
"""
import html
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from database import (
    get_db, UserDB, ThreatEventDB, DevicePostureDB,
    VPNConnectionDB, AlertDB, ActivityLogDB
)
from auth import get_uid, get_admin, get_analyst
from helpers import get_ip
from config import RATE_LIMIT_INGEST
import detection as det

threat_router  = APIRouter(prefix="/api/threats",  tags=["threat-detection"])
posture_router = APIRouter(prefix="/api/posture",   tags=["device-posture"])
limiter = Limiter(key_func=get_remote_address)


# ── Pydantic Schemas ──────────────────────────────────────────
class SecurityEventReq(BaseModel):
    """Structured security event from the endpoint agent — replaces active_window streaming."""
    tracking_key: str = Field(..., description="Agent auth key (same as monitoring key)")
    event_type: str = Field(..., description=(
        "One of: process_start, login_fail, large_download, usb_insert, "
        "firewall_off, os_unpatched, credential_tool, dns_query"
    ))
    process_name: Optional[str] = Field(None, description="For process_start / credential_tool events")
    domain:       Optional[str] = Field(None, description="For dns_query events")
    severity:     Optional[str] = Field("medium", description="low | medium | high | critical")
    details:      Optional[str] = Field(None, description="Human-readable context string")
    posture: Optional[dict] = Field(None, description=(
        "Device posture snapshot: {os_patched, antivirus_on, firewall_on, disk_encrypted}"
    ))


class PostureReportReq(BaseModel):
    """Device posture check submitted by the endpoint agent."""
    tracking_key:   str
    device_name:    str = "Unknown Device"
    os_patched:     bool = True
    antivirus_on:   bool = True
    firewall_on:    bool = True
    disk_encrypted: bool = True


class DNSEventReq(BaseModel):
    """DNS query event — matches against known-malicious domain blocklist (R6)."""
    tracking_key: str
    domain: str = Field(..., description="Fully-qualified domain name queried")


# ── Helpers ───────────────────────────────────────────────────
def _resolve_user_by_key(db: Session, tracking_key: str) -> UserDB:
    user = db.query(UserDB).filter_by(tracking_key=tracking_key.strip()).first()
    if not user:
        raise HTTPException(401, "Invalid tracking key")
    return user


def _peer_ip_for_user(db: Session, user_email: str) -> str:
    node = db.query(VPNConnectionDB).filter_by(user_email=user_email).first()
    return node.virtual_ip if node else ""


# ══════════════════════════════════════════════════════════════
# THREAT DETECTION ROUTES
# ══════════════════════════════════════════════════════════════

@threat_router.post("/ingest", status_code=202)
@limiter.limit(RATE_LIMIT_INGEST)
def ingest_security_event(
    req: SecurityEventReq,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Structured security event ingestion endpoint.
    The agent sends discrete security events (not screen titles).
    Routes to the appropriate detection rule based on event_type.
    """
    user = _resolve_user_by_key(db, req.tracking_key)
    peer_ip = _peer_ip_for_user(db, user.email)
    ip      = get_ip(request)
    fired_events = []

    etype = req.event_type.lower().strip()

    # R8: credential tool process detected
    if etype == "credential_tool" and req.process_name:
        ev = det.check_credential_tool(db, user.email, html.escape(req.process_name), peer_ip)
        if ev:
            fired_events.append(ev.event_type)

    # R6: DNS query against blocklist
    if etype == "dns_query" and req.domain:
        ev = det.check_malicious_dns(db, user.email, html.escape(req.domain), peer_ip)
        if ev:
            fired_events.append(ev.event_type)

    # R1: explicit login_fail event → check brute force threshold
    if etype == "login_fail":
        from database import ActivityLogDB
        db.add(ActivityLogDB(
            user_email=user.email,
            action="login_fail",
            ip_address=ip,
            user_agent="CyberGuard Agent",
            device_info=req.details or "Endpoint",
        ))
        db.flush()
        ev = det.check_brute_force(db, user.email, ip)
        if ev:
            fired_events.append(ev.event_type)

    # R4: inline posture snapshot
    if req.posture:
        p = req.posture
        ev = det.check_posture(
            db, user.email,
            device_name=p.get("device_name", "Unknown Device"),
            os_patched=bool(p.get("os_patched", True)),
            antivirus_on=bool(p.get("antivirus_on", True)),
            firewall_on=bool(p.get("firewall_on", True)),
            disk_encrypted=bool(p.get("disk_encrypted", True)),
            peer_ip=peer_ip,
            source="endpoint_agent",
        )
        if ev:
            fired_events.append(ev.event_type)

    # R5: large_download event with MB value in details
    if etype == "large_download":
        node = db.query(VPNConnectionDB).filter_by(user_email=user.email).first()
        if node:
            ev = det.check_large_download(db, node)
            if ev:
                fired_events.append(ev.event_type)

    # Update user last_seen
    user.last_seen = datetime.now(timezone.utc)
    db.commit()

    return {
        "status": "processed",
        "user": user.name,
        "event_type": etype,
        "detections_fired": fired_events,
        "peer_ip": peer_ip,
    }


@threat_router.post("/dns")
def report_dns_query(req: DNSEventReq, db: Session = Depends(get_db)):
    """R6: Report a DNS query for malicious-domain matching."""
    user = _resolve_user_by_key(db, req.tracking_key)
    peer_ip = _peer_ip_for_user(db, user.email)
    ev = det.check_malicious_dns(db, user.email, req.domain, peer_ip)
    db.commit()
    if ev:
        return {"status": "threat_detected", "rule": "malicious_dns", "domain": req.domain}
    return {"status": "clean", "domain": req.domain}


@threat_router.get("/events")
def list_threat_events(
    user_email:  Optional[str] = Query(None),
    severity:    Optional[str] = Query(None),
    event_type:  Optional[str] = Query(None),
    resolved:    Optional[bool] = Query(None),
    days:        int = Query(7, ge=1, le=90),
    skip:        int = Query(0, ge=0),
    limit:       int = Query(50, ge=1, le=200),
    uid: int = Depends(get_uid),
    db: Session = Depends(get_db),
):
    """List threat events with rich filtering. Admins see all; analysts filter by user."""
    curr_user = db.get(UserDB, uid)
    if not curr_user:
        raise HTTPException(404, "User not found")
    if not (curr_user.is_admin or curr_user.role in ("admin", "ciso", "analyst", "Admin", "CISO", "Analyst", "Security Analyst")):
        user_email = curr_user.email

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(ThreatEventDB).filter(ThreatEventDB.created_at >= cutoff)

    if user_email:  q = q.filter(ThreatEventDB.user_email == user_email)
    if severity:    q = q.filter(ThreatEventDB.severity == severity)
    if event_type:  q = q.filter(ThreatEventDB.event_type == event_type)
    if resolved is not None:
        q = q.filter(ThreatEventDB.resolved == resolved)

    total = q.count()
    events = q.order_by(ThreatEventDB.created_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "events": [
            {
                "id":               e.id,
                "user_email":       e.user_email,
                "peer_ip":          e.peer_ip,
                "event_type":       e.event_type,
                "mitre_tactic":     e.mitre_tactic,
                "mitre_technique":  e.mitre_technique,
                "severity":         e.severity,
                "risk_delta":       e.risk_delta,
                "details":          e.details,
                "source":           e.source,
                "resolved":         e.resolved,
                "created_at":       e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@threat_router.get("/risk-scores")
def get_risk_scores(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Return per-user risk scores for all users in the fleet."""
    users = db.query(UserDB).all()
    scores = []
    for u in users:
        score_data = det.compute_user_risk_score(db, u.email)
        # Attach posture
        posture = (
            db.query(DevicePostureDB)
            .filter_by(user_email=u.email)
            .order_by(DevicePostureDB.last_checked.desc())
            .first()
        )
        scores.append({
            **score_data,
            "user_name": u.name,
            "role": u.role,
            "posture_score": posture.posture_score if posture else 100,
            "posture_risk":  posture.risk_level   if posture else "low",
        })
    scores.sort(key=lambda x: x["risk_score"])  # Riskiest first
    return {"risk_scores": scores, "total_users": len(scores)}


@threat_router.post("/resolve/{event_id}")
def resolve_threat_event(
    event_id: int,
    uid: int = Depends(get_analyst),
    db: Session = Depends(get_db),
):
    """SOC analyst marks a threat event as resolved (triaged)."""
    event = db.query(ThreatEventDB).filter_by(id=event_id).first()
    if not event:
        raise HTTPException(404, "Threat event not found")
    event.resolved = True
    db.commit()
    return {"status": "resolved", "id": event_id, "event_type": event.event_type}


# ── Employee self-service: own threats ────────────────────────
@threat_router.get("/my-events")
def my_threat_events(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Employee view: see only threat events attributed to their own account."""
    user = db.query(UserDB).filter_by(id=uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    events = (
        db.query(ThreatEventDB)
        .filter_by(user_email=user.email)
        .order_by(ThreatEventDB.created_at.desc())
        .limit(20)
        .all()
    )
    risk_data = det.compute_user_risk_score(db, user.email)
    return {
        "user_email": user.email,
        "risk_score": risk_data["risk_score"],
        "risk_level": risk_data["risk_level"],
        "events": [
            {
                "event_type":      e.event_type,
                "mitre_technique": e.mitre_technique,
                "severity":        e.severity,
                "details":         e.details,
                "resolved":        e.resolved,
                "created_at":      e.created_at.isoformat(),
            }
            for e in events
        ],
        "what_we_collect": [
            "Security events your device reports (process names, posture checks)",
            "VPN connection metadata (IP, bytes transferred, handshake times)",
            "App login events (successful and failed)",
            "No screen contents, no keystrokes, no personal files",
        ],
    }


# ══════════════════════════════════════════════════════════════
# POSTURE ROUTES
# ══════════════════════════════════════════════════════════════

@posture_router.post("/report", status_code=202)
@limiter.limit(RATE_LIMIT_INGEST)
def report_posture(
    req: PostureReportReq,
    request: Request,
    db: Session = Depends(get_db),
):
    """R4: Agent submits device posture check. Triggers quarantine if posture fails."""
    user = _resolve_user_by_key(db, req.tracking_key)
    peer_ip = _peer_ip_for_user(db, user.email)

    ev = det.check_posture(
        db,
        user_email=user.email,
        device_name=html.escape(req.device_name),
        os_patched=req.os_patched,
        antivirus_on=req.antivirus_on,
        firewall_on=req.firewall_on,
        disk_encrypted=req.disk_encrypted,
        peer_ip=peer_ip,
        source="endpoint_agent",
    )
    db.commit()

    return {
        "status": "threat_detected" if ev else "compliant",
        "user": user.name,
        "detection": ev.event_type if ev else None,
    }


@posture_router.get("/fleet")
def fleet_posture(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Admin fleet view: posture health for every known device."""
    rows = db.query(DevicePostureDB).order_by(DevicePostureDB.last_checked.desc()).all()
    # Group by user
    by_user: dict = {}
    for r in rows:
        if r.user_email not in by_user:
            by_user[r.user_email] = []
        by_user[r.user_email].append({
            "device_name":    r.device_name,
            "os_patched":     r.os_patched,
            "antivirus_on":   r.antivirus_on,
            "firewall_on":    r.firewall_on,
            "disk_encrypted": r.disk_encrypted,
            "posture_score":  r.posture_score,
            "risk_level":     r.risk_level,
            "source":         r.source,
            "last_checked":   r.last_checked.isoformat(),
        })

    fleet_health = []
    for email, devices in by_user.items():
        avg_score = round(sum(d["posture_score"] for d in devices) / len(devices))
        fleet_health.append({
            "user_email": email,
            "devices": devices,
            "avg_posture_score": avg_score,
            "fleet_risk": (
                "critical" if avg_score <= 25 else
                "high"     if avg_score <= 50 else
                "medium"   if avg_score <= 75 else
                "low"
            ),
        })
    fleet_health.sort(key=lambda x: x["avg_posture_score"])

    total_devices  = len(rows)
    failing        = [r for r in rows if r.posture_score < 75]
    compliant      = [r for r in rows if r.posture_score == 100]

    return {
        "summary": {
            "total_devices":   total_devices,
            "compliant":       len(compliant),
            "failing":         len(failing),
            "compliance_rate": round(len(compliant) / max(total_devices, 1) * 100, 1),
        },
        "fleet": fleet_health,
    }


@posture_router.get("/user/{email}")
def user_posture(email: str, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Get posture history for a specific user's devices."""
    curr_user = db.get(UserDB, uid)
    if not curr_user:
        raise HTTPException(404, "User not found")
    if not (curr_user.is_admin or curr_user.role in ("admin", "ciso", "analyst", "Admin", "CISO", "Analyst", "Security Analyst") or curr_user.email == email):
        raise HTTPException(403, "Forbidden: You may only view your own device posture records")
    rows = (
        db.query(DevicePostureDB)
        .filter_by(user_email=email)
        .order_by(DevicePostureDB.last_checked.desc())
        .limit(10)
        .all()
    )
    if not rows:
        raise HTTPException(404, f"No posture records for {email}")
    return {
        "user_email": email,
        "devices": [
            {
                "device_name":    r.device_name,
                "os_patched":     r.os_patched,
                "antivirus_on":   r.antivirus_on,
                "firewall_on":    r.firewall_on,
                "disk_encrypted": r.disk_encrypted,
                "posture_score":  r.posture_score,
                "risk_level":     r.risk_level,
                "source":         r.source,
                "last_checked":   r.last_checked.isoformat(),
            }
            for r in rows
        ],
    }
