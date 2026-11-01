"""
CyberGuard v2.0 — Notifications & Webhook Routes
Webhook config management and outbound alert dispatch.
"""
import hmac
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from database import get_db, WebhookConfigDB, AlertDB
from schemas import WebhookConfigReq
from auth import get_uid, get_admin

logger = logging.getLogger("cyberguard.notifications")
router = APIRouter(prefix="/api/notifications", tags=["notifications"])


# ── Webhook CRUD ──────────────────────────────────────────────
@router.get("/webhooks")
def list_webhooks(uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    hooks = db.query(WebhookConfigDB).all()
    return {"webhooks": [_hook_dict(h) for h in hooks]}


@router.post("/webhooks", status_code=201)
def create_webhook(req: WebhookConfigReq, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    hook = WebhookConfigDB(
        name=req.name, url=req.url, secret=req.secret,
        events=req.events, is_active=req.is_active
    )
    db.add(hook)
    db.commit()
    db.refresh(hook)
    return _hook_dict(hook)


@router.put("/webhooks/{hook_id}")
def update_webhook(hook_id: int, req: WebhookConfigReq, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    hook = db.get(WebhookConfigDB, hook_id)
    if not hook:
        raise HTTPException(404, "Webhook not found")
    hook.name = req.name
    hook.url = req.url
    hook.secret = req.secret
    hook.events = req.events
    hook.is_active = req.is_active
    db.commit()
    return _hook_dict(hook)


@router.delete("/webhooks/{hook_id}")
def delete_webhook(hook_id: int, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    hook = db.get(WebhookConfigDB, hook_id)
    if not hook:
        raise HTTPException(404, "Webhook not found")
    db.delete(hook)
    db.commit()
    return {"message": "Deleted"}


@router.post("/webhooks/{hook_id}/test")
def test_webhook(hook_id: int, background: BackgroundTasks, uid: int = Depends(get_admin), db: Session = Depends(get_db)):
    hook = db.get(WebhookConfigDB, hook_id)
    if not hook:
        raise HTTPException(404, "Webhook not found")
    payload = {
        "event": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "CyberGuard webhook test — connection successful",
        "app": "CyberGuard v2.0"
    }
    background.add_task(_dispatch_webhook, hook.url, hook.secret, payload)
    return {"message": "Test webhook dispatched"}


# ── Alert Notifications ────────────────────────────────────────
@router.get("/recent")
def recent_notifications(limit: int = 10, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Return the most recent critical/high alerts as notification items."""
    alerts = (
        db.query(AlertDB)
        .filter(AlertDB.status == "open")
        .filter(AlertDB.severity.in_(["critical", "high"]))
        .order_by(AlertDB.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "notifications": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "category": a.category,
                "createdAt": a.created_at.isoformat() + "Z",
            }
            for a in alerts
        ],
        "unread": len(alerts)
    }


# ── Internal dispatch function ────────────────────────────────
async def _dispatch_webhook(url: str, secret: str, payload: dict):
    """Send a signed JSON payload to a webhook URL (fire-and-forget)."""
    body = json.dumps(payload, default=str)
    headers = {"Content-Type": "application/json", "User-Agent": "CyberGuard/2.0"}
    if secret:
        sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-CyberGuard-Signature"] = f"sha256={sig}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, content=body, headers=headers)
            logger.info(f"Webhook {url} → {resp.status_code}")
    except Exception as e:
        logger.error(f"Webhook dispatch failed ({url}): {e}")


def _hook_dict(h: WebhookConfigDB) -> dict:
    return {
        "id": h.id, "name": h.name, "url": h.url,
        "events": h.events, "isActive": h.is_active,
        "createdAt": h.created_at.isoformat() + "Z"
    }
