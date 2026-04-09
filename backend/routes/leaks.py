"""
CyberGuard v2.0 — Leak Routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, LeakDB
from schemas import LeakCreate, LeakUpdate
from auth import get_uid
from helpers import ldict, recalculate_score

router = APIRouter(prefix="/api/leaks", tags=["leaks"])


@router.get("/")
def list_leaks(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    leaks = db.query(LeakDB).order_by(LeakDB.created_at.desc()).all()
    return {"leaks": [ldict(l) for l in leaks], "active": sum(1 for l in leaks if l.status != "resolved"), "credentials": sum(l.credentials for l in leaks), "investigating": sum(1 for l in leaks if l.status == "investigating")}


@router.post("/", status_code=201)
def create_leak(req: LeakCreate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    l = LeakDB(title=req.title, severity=req.severity, source=req.source, credentials=req.credentials, records=req.records, status="open", details=req.details)
    db.add(l)
    db.commit()
    db.refresh(l)
    return ldict(l)


@router.put("/{lid}")
def update_leak(lid: int, req: LeakUpdate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    l = db.get(LeakDB, lid)
    if not l:
        raise HTTPException(404)
    for f in ["status", "severity", "credentials", "records", "details"]:
        val = getattr(req, f)
        if val is not None:
            setattr(l, f, val)
    db.commit()
    recalculate_score(db)
    return ldict(l)


@router.delete("/{lid}")
def delete_leak(lid: int, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    l = db.get(LeakDB, lid)
    if not l:
        raise HTTPException(404)
    db.delete(l)
    db.commit()
    return {"message": "Deleted"}
