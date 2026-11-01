"""
CyberGuard v2.0 — Domain Scan Routes
"""
import re
import socket
import ipaddress
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, AlertDB
from schemas import ScanReq
from auth import get_uid
from scan import ssl_check, header_check, port_check

router = APIRouter(prefix="/api/scan", tags=["scan"])

# SSRF protection: block scanning of internal/private networks
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(domain: str) -> bool:
    """Check if a domain resolves to a private/internal IP address."""
    try:
        ips = socket.getaddrinfo(domain, None)
        for info in ips:
            addr = ipaddress.ip_address(info[4][0])
            for net in _BLOCKED_NETWORKS:
                if addr in net:
                    return True
    except (socket.gaierror, ValueError):
        pass
    return False


@router.post("/domain")
def scan_domain(req: ScanReq, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    domain = re.sub(r"^https?://", "", req.domain).split("/")[0].strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")

    # SSRF protection: block internal/private IP targets
    if _is_private_ip(domain):
        raise HTTPException(400, "Scanning internal or private networks is not permitted")


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
