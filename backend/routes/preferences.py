"""
CyberGuard v2.0 — User Preferences Routes
GET and PUT per-user notification and UI preferences.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, UserPreferencesDB
from schemas import PreferencesUpdate
from auth import get_uid

router = APIRouter(prefix="/api/preferences", tags=["preferences"])


def _get_or_create_prefs(uid: int, db: Session) -> UserPreferencesDB:
    prefs = db.query(UserPreferencesDB).filter_by(user_id=uid).first()
    if not prefs:
        prefs = UserPreferencesDB(user_id=uid)
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    return prefs


def _prefs_dict(p: UserPreferencesDB) -> dict:
    return {
        "notifCritical":    p.notif_critical,
        "notifLeaks":       p.notif_leaks,
        "notifMl":          p.notif_ml,
        "mlAutotrain":      p.ml_autotrain,
        "mlVendorscan":     p.ml_vendorscan,
        "anomalyThreshold": p.anomaly_threshold,
        "theme":            p.theme,
    }


@router.get("/")
def get_preferences(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    prefs = _get_or_create_prefs(uid, db)
    return _prefs_dict(prefs)


@router.put("/")
def update_preferences(req: PreferencesUpdate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    prefs = _get_or_create_prefs(uid, db)

    field_map = {
        "notif_critical":    req.notif_critical,
        "notif_leaks":       req.notif_leaks,
        "notif_ml":          req.notif_ml,
        "ml_autotrain":      req.ml_autotrain,
        "ml_vendorscan":     req.ml_vendorscan,
        "anomaly_threshold": req.anomaly_threshold,
        "theme":             req.theme,
    }
    for attr, val in field_map.items():
        if val is not None:
            setattr(prefs, attr, val)

    db.commit()
    db.refresh(prefs)
    return _prefs_dict(prefs)
