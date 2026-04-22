"""
CyberGuard v2.0 — Employee Monitoring Routes
"""
import secrets
import html
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db, UserDB, EmployeeActivityDB, ActivityLogDB
from schemas import ActivityTelemetryReq
from auth import get_uid, get_admin
from helpers import get_ip

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


@router.post("/ingest")
# TODO: Implement strict rate limiting (e.g. 1 req/sec per tracking_key) for production
def ingest_telemetry(req: ActivityTelemetryReq, request: Request, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter_by(tracking_key=req.tracking_key).first()
    if not user:
        raise HTTPException(401, "Invalid tracking key")
    
    ip = get_ip(request)
    last_act = db.query(EmployeeActivityDB).filter_by(user_id=user.id).order_by(EmployeeActivityDB.timestamp.desc()).first()
    
    # Optional logic: only keep the latest status per user, or log history? Let's log history.
    activity = EmployeeActivityDB(
        user_id=user.id,
        active_window=html.escape(req.active_window[:300]),
        device_ip=ip,
        status=req.status
    )
    db.add(activity)

    if not last_act or last_act.active_window != req.active_window:
        log = ActivityLogDB(
            user_email=user.email,
            action="desktop_monitor",
            page=html.escape(req.active_window[:100]),
            ip_address=ip,
            user_agent="CyberGuard Agent",
            device_info="Employee Machine"
        )
        db.add(log)
    
    user.last_seen = datetime.utcnow()
    db.commit()
    
    return {"status": "ok"}


@router.get("/users")
def get_monitored_users(uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    results = []
    
    for u in users:
        # Get the latest activity for the user
        act = db.query(EmployeeActivityDB).filter_by(user_id=u.id).order_by(EmployeeActivityDB.timestamp.desc()).first()
        
        # Don't show admin accounts or unmonitored accounts unless specified
        results.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "role": u.role,
            "tracking_key": u.tracking_key,
            "active_window": act.active_window if act else "Unknown",
            "device_ip": act.device_ip if act else "N/A",
            "status": act.status if act else "offline",
            "last_active": act.timestamp.isoformat() + "Z" if act else None
        })
        
    return {"employees": results}


@router.post("/generate-key/{user_id}")
def generate_tracking_key(user_id: int, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(404, "User not found")
        
    new_key = f"cg_trk_{secrets.token_urlsafe(16)}"
    u.tracking_key = new_key
    db.commit()
    
    return {"id": u.id, "tracking_key": u.tracking_key}
