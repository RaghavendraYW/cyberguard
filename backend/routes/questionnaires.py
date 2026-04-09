"""
CyberGuard v2.0 — Questionnaire Routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, QuestionnaireDB
from schemas import QCreate, QUpdate
from auth import get_uid
from helpers import qdict

router = APIRouter(prefix="/api/questionnaires", tags=["questionnaires"])


@router.get("/")
def list_q(status: str = "", uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    qs = db.query(QuestionnaireDB)
    if status:
        qs = qs.filter_by(status=status)
    qs = qs.order_by(QuestionnaireDB.created_at.desc()).all()
    return {"questionnaires": [qdict(q) for q in qs], "total": len(qs)}


@router.post("/", status_code=201)
def create_q(req: QCreate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    q = QuestionnaireDB(title=req.title, framework=req.framework, vendor=req.vendor, total=req.total, answered=0, status="pending", due_date=req.due, notes=req.notes)
    db.add(q)
    db.commit()
    db.refresh(q)
    return qdict(q)


@router.put("/{qid}")
def update_q(qid: int, req: QUpdate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    q = db.get(QuestionnaireDB, qid)
    if not q:
        raise HTTPException(404)
    for f in ["title", "framework", "vendor", "total", "answered", "status", "due_date", "notes"]:
        val = getattr(req, f, None)
        if val is not None:
            setattr(q, f, val)
    if q.answered >= q.total:
        q.status = "completed"
    elif q.answered > 0:
        q.status = "in_progress"
    db.commit()
    return qdict(q)


@router.delete("/{qid}")
def delete_q(qid: int, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    q = db.get(QuestionnaireDB, qid)
    if not q:
        raise HTTPException(404)
    db.delete(q)
    db.commit()
    return {"message": "Deleted"}
