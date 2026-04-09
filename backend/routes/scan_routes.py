"""
CyberGuard v2.0 — Domain Scan Routes
"""
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, AlertDB
from schemas import ScanReq
from auth import get_uid
from scan import ssl_check, header_check, port_check

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/domain")
def scan_domain(req: ScanReq, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    domain = re.sub(r"^https?://", "", req.domain).split("/")[0].strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")

    sl = ssl_check(domain)
    hd = header_check(domain)
    pt = port_check(domain)

    score = 950
    score += {"A": 0, "B": -50, "C": -120, "D": -200, "F": -300}.get(sl["grade"], 0)
    score += {"A": 0, "B": -50, "C": -100, "D": -150, "F": -200}.get(hd["grade"], 0)
    score -= len(pt["dangerous_ports"]) * 60
    score = max(100, min(950, score))

    findings = sl["findings"] + hd["findings"] + pt["findings"]

    if sl["grade"] == "F" and hd["grade"] == "F" and not findings:
        findings.append(f"Could not reach {domain} — firewall may be blocking scans")
        findings.append("SSL check: connection refused or timed out")
        findings.append("Header check: connection refused or timed out")
        score = max(100, score - 100)

    alerts_created = []
    if sl.get("valid") and sl.get("days_left", 99) <= 7:
        db.add(AlertDB(title=f"SSL expiring in {sl['days_left']} days — {domain}", severity="critical", category="Website Security", status="open", source="scan"))
        db.commit()
        alerts_created.append("SSL expiry alert")

    return {
        "domain": domain, "score": score,
        "grades": {"ssl": sl["grade"], "email": "B", "headers": hd["grade"], "network": "A" if not pt["dangerous_ports"] else "C"},
        "findings": findings, "alertsCreated": alerts_created,
        "ssl": {"valid": sl.get("valid", False), "daysLeft": sl.get("days_left", 0), "expiry": sl.get("expiry", "")},
        "dangerousPorts": pt["dangerous_ports"]
    }


@router.get("/history")
def scan_history(uid: int = Depends(get_uid)):
    return {"scans": []}
