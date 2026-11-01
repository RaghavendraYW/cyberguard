"""
CyberGuard v2.0 — Alert Routes
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, AlertDB
from schemas import AlertCreate, AlertUpdate, ClassifyReq
from auth import get_uid, get_analyst
from helpers import adict, recalculate_score
from ml.engine import threat_classifier

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/")
def list_alerts(
    severity: str = "", status: str = "",
    skip: int = 0, limit: int = 100,
    uid: int = Depends(get_uid), db: Session = Depends(get_db)
):
    q = db.query(AlertDB)
    if severity:
        q = q.filter_by(severity=severity)
    if status:
        q = q.filter_by(status=status)
    alerts = sorted(q.all(), key=lambda a: (0 if a.status == "open" else 1, {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.severity, 4)))
    total = len(alerts)
    page = alerts[skip:skip + limit]
    return {"alerts": [adict(a) for a in page], "total": total, "skip": skip, "limit": limit,
            "open": sum(1 for a in alerts if a.status == "open"),
            "critical": sum(1 for a in alerts if a.severity == "critical" and a.status == "open")}


@router.post("/", status_code=201)
def create_alert(req: AlertCreate, uid: int = Depends(get_analyst), db: Session = Depends(get_db)):
    ml = threat_classifier.predict(f"{req.title} {req.description}")
    sev = req.severity
    if ml.get("label") in ("phishing", "malware") and ml.get("confidence", 0) > 0.7:
        sev = "critical" if ml["label"] == "malware" else "high"
    a = AlertDB(title=req.title, severity=sev, category=req.category, description=req.description,
                source=req.source, ml_score=ml.get("confidence", 0), assignee=req.assignee)
    db.add(a)
    db.commit()
    db.refresh(a)
    recalculate_score(db)
    d = adict(a)
    d["mlClassification"] = ml
    return d


@router.post("/bulk-acknowledge")
def bulk_ack(uid: int = Depends(get_analyst), db: Session = Depends(get_db)):
    alerts = db.query(AlertDB).filter_by(status="open").all()
    for a in alerts:
        a.status = "acknowledged"
    db.commit()
    return {"acknowledged": len(alerts)}


@router.post("/classify")
def classify_alert(req: ClassifyReq, uid: int = Depends(get_uid)):
    return threat_classifier.predict(req.text)


@router.get("/{aid}")
def get_alert(aid: int, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    a = db.get(AlertDB, aid)
    if not a:
        raise HTTPException(404)
    d = adict(a)
    d["mlClassification"] = threat_classifier.predict(a.title + " " + a.description)
    return d


@router.put("/{aid}")
def update_alert(aid: int, req: AlertUpdate, uid: int = Depends(get_analyst), db: Session = Depends(get_db)):
    a = db.get(AlertDB, aid)
    if not a:
        raise HTTPException(404)
    for f in ["title", "severity", "category", "status", "description", "assignee"]:
        val = getattr(req, f)
        if val is not None:
            setattr(a, f, val)
    a.updated_at = datetime.now(timezone.utc)
    db.commit()
    recalculate_score(db)
    return adict(a)


@router.delete("/{aid}")
def delete_alert(aid: int, uid: int = Depends(get_analyst), db: Session = Depends(get_db)):
    a = db.get(AlertDB, aid)
    if not a:
        raise HTTPException(404)
    db.delete(a)
    db.commit()
    return {"message": "Deleted"}
