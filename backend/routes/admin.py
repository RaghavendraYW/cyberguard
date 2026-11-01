"""
CyberGuard v2.0 — Admin Routes
Includes audit trail for all admin actions, GDPR data export, and SSO stub.
"""
import json
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
import io
import csv
from sqlalchemy import func
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from database import get_db, UserDB, ActivityLogDB, VendorDB, AlertDB, LeakDB, SecurityScoreDB, ReportDB, UserPreferencesDB, VPNConnectionDB
from schemas import CreateUserReq, UpdateUserReq
from auth import get_admin, get_analyst
from helpers import udict, logdict

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _is_online(dt, threshold_minutes=5):
    if not dt:
        return False
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt >= (now - timedelta(minutes=threshold_minutes))


@router.get("/users")
def admin_users(uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    result = []
    for u in users:
        recent = db.query(ActivityLogDB).filter_by(user_email=u.email).order_by(ActivityLogDB.timestamp.desc()).first()
        anom = db.query(ActivityLogDB).filter_by(user_email=u.email, is_anomaly=True).count()
        total = db.query(ActivityLogDB).filter_by(user_email=u.email).count()
        is_user_online = _is_online(u.last_seen)
        result.append({
            **udict(u),
            "lastAction": recent.action if recent else None,
            "lastPage": recent.page if recent else None,
            "lastIp": recent.ip_address if recent else None,
            "lastDevice": recent.device_info if recent else None,
            "lastSeen": u.last_seen.isoformat() if u.last_seen else None,
            "online": is_user_online,
            "anomalyCount": anom, "totalActions": total,
            "riskLevel": "critical" if anom > 5 else "high" if anom > 2 else "low"
        })
    online_count = sum(1 for u in users if _is_online(u.last_seen))
    return {"users": result, "total": len(result), "online": online_count}


@router.get("/stats")
def admin_stats(uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    all_users = db.query(UserDB).all()
    online = sum(1 for u in all_users if _is_online(u.last_seen))
    today_logs = db.query(ActivityLogDB).count()
    top = db.query(ActivityLogDB.user_email, func.count(ActivityLogDB.id).label("cnt")).group_by(ActivityLogDB.user_email).order_by(func.count(ActivityLogDB.id).desc()).limit(5).all()
    return {"totalUsers": len(all_users), "onlineNow": online, "totalLogs": db.query(ActivityLogDB).count(), "totalAnomalies": db.query(ActivityLogDB).filter_by(is_anomaly=True).count(), "todayLogs": today_logs, "topUsersToday": [{"email": r[0], "actions": r[1]} for r in top]}


@router.get("/activity-feed")
def activity_feed(limit: int = 50, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    logs = db.query(ActivityLogDB).order_by(ActivityLogDB.timestamp.desc()).limit(limit).all()
    return {"feed": [logdict(l) for l in logs]}


@router.get("/user/{email}/activity")
def user_activity(email: str, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    logs = db.query(ActivityLogDB).filter_by(user_email=email).order_by(ActivityLogDB.timestamp.desc()).limit(100).all()
    anom = db.query(ActivityLogDB).filter_by(user_email=email, is_anomaly=True).count()
    return {"logs": [logdict(l) for l in logs], "totalLogs": len(logs), "anomalyCount": anom}


@router.get("/user/{email}/download-logs")
def download_user_activity(email: str, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    # Fetch all logs for this user
    logs = db.query(ActivityLogDB).filter_by(user_email=email).order_by(ActivityLogDB.timestamp.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Timestamp ID', 'Action Executed', 'Window/Page', 'IP Address', 'Device/User Agent', 'Is ML Anomaly?', 'Anomaly Confidence'])
    
    # Write rows
    for l in logs:
        writer.writerow([
            l.timestamp.isoformat() + "Z",
            l.action,
            l.page or "N/A",
            l.ip_address or "Unknown",
            l.device_info or l.user_agent or "Unknown",
            "YES" if l.is_anomaly else "No",
            f"{l.anomaly_score * 100:.1f}%" if l.anomaly_score else "N/A"
        ])
        
    output.seek(0)
    
    filename = f"cyberguard_logs_{email.split('@')[0]}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}.csv"
    headers = {
        'Content-Disposition': f'attachment; filename="{filename}"'
    }
    
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)


@router.post("/users/create")
def admin_create_user(req: CreateUserReq, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    if db.query(UserDB).filter_by(email=req.email.lower().strip()).first():
        raise HTTPException(400, "Email already exists")
    u = UserDB(name=req.name, email=req.email.lower().strip(), password_hash=generate_password_hash(req.password), role=req.role, is_admin=req.isAdmin, company=req.company)
    db.add(u)
    db.commit()
    db.refresh(u)
    _audit(db, uid, "admin_create_user", f"Created user: {u.email} role={u.role}")

    # Auto-provision VPN node so the new user appears on the VPN page immediately
    existing_vpn = db.query(VPNConnectionDB).filter_by(user_email=u.email).first()
    if not existing_vpn:
        used = {
            int(n.virtual_ip.split(".")[-1])
            for n in db.query(VPNConnectionDB).all()
            if n.virtual_ip and n.virtual_ip.startswith("10.8.0.")
        }
        next_host = 2
        while next_host in used and next_host < 254:
            next_host += 1
        db.add(VPNConnectionDB(
            user_name=u.name,
            user_email=u.email,
            device_name="Pending First Login",
            protocol="WireGuard",
            virtual_ip=f"10.8.0.{next_host}",
            endpoint_ip="0.0.0.0",
            server_location="Auto-Assigned Gateway",
            status="disconnected",
            bytes_sent=0.0,
            bytes_received=0.0,
            latency_ms=0,
            posture_status="compliant",
            killswitch_active=True,
        ))

    db.commit()
    return udict(u)


@router.put("/users/{user_id}")
def admin_update_user(user_id: int, req: UpdateUserReq, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(404)
    changes = []
    if req.isAdmin is not None:
        u.is_admin = req.isAdmin
        changes.append(f"isAdmin={req.isAdmin}")
    if req.role:
        u.role = req.role
        changes.append(f"role={req.role}")
    if req.name:
        u.name = req.name
        changes.append(f"name={req.name}")
    if req.password:
        u.password_hash = generate_password_hash(req.password)
        changes.append("password=***")
    _audit(db, uid, "admin_update_user", f"Updated user {u.email}: {', '.join(changes)}")
    db.commit()
    return udict(u)


@router.delete("/users/{user_id}")
def admin_delete_user(user_id: int, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(404)
    if u.id == uid:
        raise HTTPException(400, "Cannot delete yourself")
    _audit(db, uid, "admin_delete_user", f"Deleted user: {u.email} (id={u.id})")
    db.delete(u)
    db.commit()
    return {"message": "Deleted"}


# ── GDPR Data Export ──────────────────────────────────────────
@router.get("/users/{user_id}/export")
def export_user_data(user_id: int, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    """GDPR-compliant full data export for a user. Returns all user data as JSON."""
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(404, "User not found")

    # Gather all user-related data
    logs = db.query(ActivityLogDB).filter_by(user_email=u.email).order_by(ActivityLogDB.timestamp.desc()).all()
    prefs = db.query(UserPreferencesDB).filter_by(user_id=u.id).first()

    export = {
        "export_metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat() + "Z",
            "exported_by_admin_id": uid,
            "gdpr_article": "Art. 20 — Right to data portability",
        },
        "user_profile": {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "role": u.role,
            "is_admin": u.is_admin,
            "company": u.company,
            "domain": getattr(u, "domain", ""),
            "created_at": u.created_at.isoformat() + "Z" if u.created_at else None,
            "last_seen": u.last_seen.isoformat() + "Z" if u.last_seen else None,
        },
        "preferences": {
            "theme": prefs.theme if prefs else "dark",
            "notif_critical": prefs.notif_critical if prefs else True,
            "notif_leaks": prefs.notif_leaks if prefs else True,
            "notif_ml": prefs.notif_ml if prefs else True,
            "anomaly_threshold": prefs.anomaly_threshold if prefs else 0.7,
        } if prefs else None,
        "activity_logs": [logdict(l) for l in logs],
        "total_activities": len(logs),
        "anomaly_count": sum(1 for l in logs if l.is_anomaly),
    }

    _audit(db, uid, "admin_export_user_data", f"GDPR data export for user: {u.email}")
    db.commit()

    return JSONResponse(content=export, headers={
        "Content-Disposition": f'attachment; filename="cyberguard_gdpr_export_{u.email.split("@")[0]}_{datetime.now(timezone.utc).strftime("%Y%m%d")}.json"'
    })


@router.get("/sso/saml")
def saml_stub(uid: int = Depends(get_admin)):
    """Placeholder for SAML2 SSO integration. Returns configuration guidance."""
    return {
        "status": "not_configured",
        "protocol": "SAML 2.0",
        "message": "SSO/SAML2 integration is available for Enterprise plan. Contact support to configure.",
        "documentation": "https://docs.cyberguard.io/sso/saml2",
        "supported_providers": ["Okta", "Azure AD", "Google Workspace", "OneLogin", "Auth0"],
        "required_config": {
            "SAML_ENTITY_ID": "Your SAML Entity ID",
            "SAML_SSO_URL": "Your IdP SSO URL",
            "SAML_CERTIFICATE": "Base64-encoded X.509 certificate",
            "SAML_ACS_URL": "/api/admin/sso/saml/acs",
        }
    }


# ── Audit Trail Helper ────────────────────────────────────────
def _audit(db: Session, admin_uid: int, action: str, detail: str = ""):
    """Log an admin action to the activity log for audit trail."""
    admin = db.get(UserDB, admin_uid)
    admin_email = admin.email if admin else f"uid:{admin_uid}"
    db.add(ActivityLogDB(
        user_email=admin_email,
        action=action,
        page="admin",
        ip_address="",
        device_info=detail[:300] if detail else "",
    ))

