"""
CyberGuard v2.0 — Dashboard Routes
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db, VendorDB, AlertDB, LeakDB, SecurityScoreDB, ActivityLogDB
from auth import get_uid
from helpers import grade
from ml.engine import ml_summary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    vendors = db.query(VendorDB).all()
    alerts = db.query(AlertDB).all()
    leaks = db.query(LeakDB).all()
    sc = db.query(SecurityScoreDB).order_by(SecurityScoreDB.created_at.desc()).first()
    score = sc.score if sc else 742
    open_a = [a for a in alerts if a.status == "open"]
    scores = db.query(SecurityScoreDB).order_by(SecurityScoreDB.created_at.desc()).limit(7).all()
    trend = [s.score for s in reversed(scores)] or [score] * 7
    anom = db.query(ActivityLogDB).filter_by(is_anomaly=True).count()
    dist = {k: sum(1 for a in open_a if a.severity == k) for k in ["critical", "high", "medium", "low"]}
    return {
        "score": score, "grade": grade(score), "openAlerts": len(open_a), "criticalAlerts": dist["critical"],
        "vendorCount": len(vendors), "activeLeaks": sum(1 for l in leaks if l.status != "resolved"),
        "anomaliesDetected": anom, "industryPct": 73, "scoreTrend": trend, "mlStatus": ml_summary(), "riskDist": dist
    }
