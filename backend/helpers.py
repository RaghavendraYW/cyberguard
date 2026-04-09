"""
CyberGuard v2.0 — Helper Functions
Scoring, grading, serialization, and utility functions.
"""
from datetime import datetime
from database import (
    VendorDB, AlertDB, LeakDB, ActivityLogDB, SecurityScoreDB
)


def grade(s):
    for t, g in [(900, "A+"), (850, "A"), (800, "A-"), (750, "B+"), (700, "B"),
                 (650, "B-"), (600, "C+"), (550, "C"), (450, "D")]:
        if s >= t:
            return g
    return "F"


def risk_level(s):
    return "low" if s >= 800 else "medium" if s >= 650 else "high" if s >= 450 else "critical"


def recalculate_score(db):
    """Recalculate security score based on current state and save it."""
    vendors    = db.query(VendorDB).all()
    alerts     = db.query(AlertDB).filter_by(status="open").all()
    leaks      = db.query(LeakDB).filter(LeakDB.status != "resolved").all()
    anom_count = db.query(ActivityLogDB).filter_by(is_anomaly=True).count()

    score = 950
    for a in alerts:
        score -= {"critical": 40, "high": 20, "medium": 10, "low": 5}.get(a.severity, 0)
    for v in vendors:
        score -= {"critical": 30, "high": 15, "medium": 5, "low": 0}.get(risk_level(v.score), 0)
    score -= len(leaks) * 25
    score -= min(anom_count * 2, 50)
    score = max(100, min(950, score))

    db.add(SecurityScoreDB(score=score, grade=grade(score)))
    db.commit()
    return score


def get_device(ua):
    if any(x in ua for x in ["Mobile", "Android", "iPhone"]):
        return "Mobile"
    if "Windows" in ua:
        return "Windows PC"
    if "Mac" in ua:
        return "MacBook"
    if "Linux" in ua:
        return "Linux"
    return "Unknown"


def get_ip(req):
    ip = req.headers.get("x-forwarded-for", "")
    if not ip and req.client:
        ip = req.client.host
    return (ip.split(",")[0].strip() if "," in ip else ip) or "127.0.0.1"


# ── Serialization helpers ─────────────────────────────────────
def udict(u):
    return {
        "id": u.id, "name": u.name, "email": u.email, "role": u.role,
        "isAdmin": u.is_admin, "company": u.company, "domain": getattr(u, "domain", ""),
        "initials": "".join(w[0] for w in u.name.split()[:2]).upper()
    }


def vdict(v, vendor_risk_scorer=None):
    d = {
        "id": v.id, "name": v.name, "domain": v.domain, "category": v.category,
        "criticality": v.criticality, "score": v.score, "issues": v.issues,
        "status": v.status, "contact": v.contact, "notes": v.notes, "trend": v.trend,
        "lastScanned": v.last_scanned, "risk": risk_level(v.score),
        "createdAt": v.created_at.isoformat()
    }
    if vendor_risk_scorer:
        r = vendor_risk_scorer.predict(d)
        d["mlRisk"] = r["risk"]
        d["mlConfidence"] = r.get("confidence", 0)
        d["mlProbabilities"] = r.get("probabilities", {})
    else:
        d["mlRisk"] = risk_level(v.score)
        d["mlConfidence"] = 0
        d["mlProbabilities"] = {}
    return d


def adict(a):
    return {
        "id": a.id, "title": a.title, "severity": a.severity, "category": a.category,
        "status": a.status, "description": a.description, "source": a.source,
        "mlScore": round(a.ml_score, 3), "createdAt": a.created_at.isoformat(),
        "updatedAt": a.updated_at.isoformat()
    }


def ldict(l):
    return {
        "id": l.id, "title": l.title, "severity": l.severity, "source": l.source,
        "credentials": l.credentials, "records": l.records, "status": l.status,
        "details": l.details, "createdAt": l.created_at.isoformat()
    }


def qdict(q):
    pct = round((q.answered / q.total) * 100) if q.total > 0 else 0
    return {
        "id": q.id, "title": q.title, "framework": q.framework, "vendor": q.vendor,
        "total": q.total, "answered": q.answered, "status": q.status, "due": q.due_date,
        "notes": q.notes, "percent": pct, "createdAt": q.created_at.isoformat()
    }


def logdict(l):
    return {
        "id": l.id, "userEmail": l.user_email, "action": l.action,
        "ipAddress": l.ip_address, "deviceInfo": l.device_info, "page": l.page,
        "timestamp": l.timestamp.isoformat(), "isAnomaly": l.is_anomaly,
        "anomalyScore": round(l.anomaly_score, 3)
    }
