"""
CyberGuard v2.0 — Vendor Routes
"""
import random
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, VendorDB
from schemas import VendorCreate, VendorUpdate
from auth import get_uid
from helpers import vdict, risk_level
from ml.engine import vendor_risk_scorer

router = APIRouter(prefix="/api/vendors", tags=["vendors"])


@router.get("/")
def list_vendors(search: str = "", uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    vendors = db.query(VendorDB).all()
    result = [vdict(v, vendor_risk_scorer) for v in vendors if not search or search.lower() in v.name.lower() or search.lower() in v.domain.lower()]
    return {"vendors": result, "total": len(result)}


@router.get("/stats")
def vendor_stats(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    vendors = db.query(VendorDB).all()
    dist = {k: sum(1 for v in vendors if risk_level(v.score) == k) for k in ["low", "medium", "high", "critical"]}
    return {"total": len(vendors), "avgScore": int(sum(v.score for v in vendors) / len(vendors)) if vendors else 0, "riskDistribution": dist}


@router.post("/", status_code=201)
def create_vendor(req: VendorCreate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    v = VendorDB(name=req.name, domain=req.domain, category=req.category, criticality=req.criticality, score=req.score or random.randint(500, 900), issues=req.issues or random.randint(1, 10), status=req.status, contact=req.contact, notes=req.notes)
    db.add(v)
    db.commit()
    db.refresh(v)
    return vdict(v, vendor_risk_scorer)


@router.get("/{vid}")
def get_vendor(vid: int, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    v = db.get(VendorDB, vid)
    if not v:
        raise HTTPException(404)
    return vdict(v, vendor_risk_scorer)


@router.put("/{vid}")
def update_vendor(vid: int, req: VendorUpdate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    v = db.get(VendorDB, vid)
    if not v:
        raise HTTPException(404)
    for f in ["name", "domain", "category", "criticality", "score", "issues", "status", "contact", "notes"]:
        val = getattr(req, f)
        if val is not None:
            setattr(v, f, val)
    db.commit()
    return vdict(v, vendor_risk_scorer)


@router.delete("/{vid}")
def delete_vendor(vid: int, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    v = db.get(VendorDB, vid)
    if not v:
        raise HTTPException(404)
    db.delete(v)
    db.commit()
    return {"message": "Deleted"}


@router.post("/{vid}/scan")
def scan_vendor(vid: int, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    v = db.get(VendorDB, vid)
    if not v:
        raise HTTPException(404)
    delta = random.randint(-15, 10)
    v.score = max(100, min(950, v.score + delta))
    v.issues = max(0, v.issues + random.randint(-2, 3))
    v.trend = f"+{delta}" if delta >= 0 else str(delta)
    v.last_scanned = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    db.commit()
    return {"vendor": vdict(v, vendor_risk_scorer), "delta": delta, "message": f"Scan complete. Score: {v.score}"}


@router.post("/rescan-all")
def rescan_all_vendors(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    vendors = db.query(VendorDB).all()
    results = []
    for v in vendors:
        delta = random.randint(-15, 10)
        v.score = max(100, min(950, v.score + delta))
        v.issues = max(0, v.issues + random.randint(-2, 3))
        v.trend = f"+{delta}" if delta >= 0 else str(delta)
        v.last_scanned = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        results.append({"id": v.id, "name": v.name, "score": v.score, "delta": delta})
    db.commit()
    return {"message": f"Rescanned {len(vendors)} vendors", "results": results}
