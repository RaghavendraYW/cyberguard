"""
CyberGuard v2.0 — Admin Routes
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from database import get_db, UserDB, ActivityLogDB
from schemas import CreateUserReq, UpdateUserReq
from auth import get_admin
from helpers import udict, logdict

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users")
def admin_users(uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    result = []
    online_threshold = datetime.utcnow() - timedelta(minutes=5)
    for u in users:
        recent = db.query(ActivityLogDB).filter_by(user_email=u.email).order_by(ActivityLogDB.timestamp.desc()).first()
        anom = db.query(ActivityLogDB).filter_by(user_email=u.email, is_anomaly=True).count()
        total = db.query(ActivityLogDB).filter_by(user_email=u.email).count()
        result.append({
            **udict(u),
            "lastAction": recent.action if recent else None,
            "lastPage": recent.page if recent else None,
            "lastIp": recent.ip_address if recent else None,
            "lastDevice": recent.device_info if recent else None,
            "lastSeen": u.last_seen.isoformat() if u.last_seen else None,
            "online": bool(u.last_seen and u.last_seen >= online_threshold),
            "anomalyCount": anom, "totalActions": total,
            "riskLevel": "critical" if anom > 5 else "high" if anom > 2 else "low"
        })
    return {"users": result, "total": len(result), "online": sum(1 for u in users if u.last_seen and u.last_seen >= online_threshold)}


@router.get("/stats")
def admin_stats(uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    online = db.query(UserDB).filter(UserDB.last_seen >= datetime.utcnow() - timedelta(minutes=5)).count()
    today_logs = db.query(ActivityLogDB).filter(ActivityLogDB.timestamp >= today).count()
    top = db.query(ActivityLogDB.user_email, func.count(ActivityLogDB.id).label("cnt")).filter(ActivityLogDB.timestamp >= today).group_by(ActivityLogDB.user_email).order_by(func.count(ActivityLogDB.id).desc()).limit(5).all()
    return {"totalUsers": db.query(UserDB).count(), "onlineNow": online, "totalLogs": db.query(ActivityLogDB).count(), "totalAnomalies": db.query(ActivityLogDB).filter_by(is_anomaly=True).count(), "todayLogs": today_logs, "topUsersToday": [{"email": r[0], "actions": r[1]} for r in top]}


@router.get("/activity-feed")
def activity_feed(limit: int = 50, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    logs = db.query(ActivityLogDB).order_by(ActivityLogDB.timestamp.desc()).limit(limit).all()
    return {"feed": [logdict(l) for l in logs]}


@router.get("/user/{email}/activity")
def user_activity(email: str, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    logs = db.query(ActivityLogDB).filter_by(user_email=email).order_by(ActivityLogDB.timestamp.desc()).limit(100).all()
    anom = db.query(ActivityLogDB).filter_by(user_email=email, is_anomaly=True).count()
    return {"logs": [logdict(l) for l in logs], "totalLogs": len(logs), "anomalyCount": anom}


@router.post("/users/create")
def admin_create_user(req: CreateUserReq, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    if db.query(UserDB).filter_by(email=req.email.lower().strip()).first():
        raise HTTPException(400, "Email already exists")
    u = UserDB(name=req.name, email=req.email.lower().strip(), password_hash=generate_password_hash(req.password), role=req.role, is_admin=req.isAdmin, company=req.company)
    db.add(u)
    db.commit()
    db.refresh(u)
    return udict(u)


@router.put("/users/{user_id}")
def admin_update_user(user_id: int, req: UpdateUserReq, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(404)
    if req.isAdmin is not None:
        u.is_admin = req.isAdmin
    if req.role:
        u.role = req.role
    if req.name:
        u.name = req.name
    if req.password:
        u.password_hash = generate_password_hash(req.password)
    db.commit()
    return udict(u)


@router.delete("/users/{user_id}")
def admin_delete_user(user_id: int, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    u = db.get(UserDB, user_id)
    if not u:
        raise HTTPException(404)
    if u.id == uid:
        raise HTTPException(400, "Cannot delete yourself")
    db.delete(u)
    db.commit()
    return {"message": "Deleted"}
