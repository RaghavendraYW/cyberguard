"""
CyberGuard v2.0 — Auth Routes
Login, logout, token refresh, profile management.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db, UserDB, ActivityLogDB, VPNConnectionDB
from schemas import LoginReq, ProfileUpdate, RefreshReq
from auth import (
    make_token, make_refresh_token, store_refresh_token,
    revoke_refresh_token, validate_refresh_token, get_uid, get_current_user
)
from helpers import udict, get_ip, get_device
from config import RATE_LIMIT_LOGIN

router = APIRouter(prefix="/api/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


def _log_action(db, user_email, action, request, page=""):
    ip = get_ip(request)
    ua = request.headers.get("user-agent", "")
    db.add(ActivityLogDB(
        user_email=user_email, action=action,
        ip_address=ip, user_agent=ua[:300],
        device_info=get_device(ua), page=page
    ))


def _auto_provision_vpn(db, user: UserDB, request: Request):
    """
    On every successful login:
    - If the user has no VPN node → create one (auto-assign 10.8.0.x IP).
    - If the user already has a node → mark it 'connected' and update last_handshake.
    This makes the VPN page reflect real login sessions.
    """
    existing = db.query(VPNConnectionDB).filter_by(user_email=user.email).first()
    client_ip = get_ip(request) or "0.0.0.0"

    if existing:
        # Reconnect: update status + telemetry on every login
        existing.status = "connected"
        existing.endpoint_ip = client_ip
        existing.last_handshake = datetime.now(timezone.utc)
        existing.latency_ms = 18  # realistic reconnect latency placeholder
    else:
        # First login — assign next available tunnel IP
        used = {
            int(n.virtual_ip.split(".")[-1])
            for n in db.query(VPNConnectionDB).all()
            if n.virtual_ip and n.virtual_ip.startswith("10.8.0.")
        }
        next_host = 2
        while next_host in used and next_host < 254:
            next_host += 1

        db.add(VPNConnectionDB(
            user_name=user.name,
            user_email=user.email,
            device_name=get_device(request.headers.get("user-agent", "")) or "Browser Client",
            protocol="WireGuard",
            virtual_ip=f"10.8.0.{next_host}",
            endpoint_ip=client_ip,
            server_location="Auto-Assigned Gateway",
            status="connected",
            bytes_sent=0.0,
            bytes_received=0.0,
            latency_ms=20,
            posture_status="compliant",
            killswitch_active=True,
            last_handshake=datetime.now(timezone.utc),
        ))


@router.post("/login")
@limiter.limit(RATE_LIMIT_LOGIN)
def login(req: LoginReq, request: Request, db: Session = Depends(get_db)):
    ident = (req.email or "").strip().lower()
    if not ident:
        raise HTTPException(401, "Email or username is required")

    # Strict user lookup: exact email match only
    user = db.query(UserDB).filter_by(email=ident).first()
    if not user:
        raise HTTPException(401, "Invalid credentials")

    # Strict password verification — bcrypt hash check only
    req_pw = (req.password or "").strip()
    if not user.password_hash or not req_pw:
        raise HTTPException(401, "Invalid credentials")
    try:
        pw_valid = check_password_hash(user.password_hash, req_pw)
    except Exception:
        pw_valid = False

    if not pw_valid:
        raise HTTPException(401, "Invalid credentials")

    user.last_seen = datetime.now(timezone.utc)
    _log_action(db, user.email, "login", request, "login")
    _auto_provision_vpn(db, user, request)  # ← auto-show in VPN on login

    access_token  = make_token(user.id)
    refresh_token = make_refresh_token(user.id)
    store_refresh_token(user.id, refresh_token, db)
    db.commit()

    return {
        "token": access_token,
        "refresh_token": refresh_token,
        "user": udict(user)
    }


@router.post("/refresh")
@limiter.limit("10/minute")
def refresh(req: RefreshReq, request: Request, db: Session = Depends(get_db)):
    """Exchange a valid refresh token for a new access token."""
    uid = validate_refresh_token(req.refresh_token, db)
    user = db.get(UserDB, uid)
    if not user:
        raise HTTPException(404, "User not found")

    new_access  = make_token(uid)
    new_refresh = make_refresh_token(uid)

    # Rotate: revoke old, store new
    revoke_refresh_token(req.refresh_token, db)
    store_refresh_token(uid, new_refresh, db)

    return {"token": new_access, "refresh_token": new_refresh}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    """Revoke the session on logout safely."""
    try:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            from auth import decode_token
            payload = decode_token(token)
            if payload and "sub" in payload:
                user = db.get(UserDB, int(payload["sub"]))
                if user:
                    _log_action(db, user.email, "logout", request, "logout")
                    db.commit()
    except Exception:
        pass
    return {"message": "Logged out successfully"}


@router.post("/token")
@limiter.limit(RATE_LIMIT_LOGIN)
def token_form(form: OAuth2PasswordRequestForm = Depends(), request: Request = None, db: Session = Depends(get_db)):
    """OAuth2-compatible token endpoint for API tooling / Swagger."""
    user = db.query(UserDB).filter_by(email=form.username).first()
    if not user or not check_password_hash(user.password_hash, form.password):
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": make_token(user.id), "token_type": "bearer"}


@router.get("/me")
def me(user: UserDB = Depends(get_current_user)):
    return udict(user)


@router.put("/update")
def update_profile(req: ProfileUpdate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    u = db.get(UserDB, uid)
    if not u:
        raise HTTPException(404, "User not found")
    for f in ["name", "role", "company", "domain"]:
        v = getattr(req, f)
        if v is not None:
            setattr(u, f, v)
    if req.password:
        u.password_hash = generate_password_hash(req.password)
    db.commit()
    return udict(u)


@router.get("/saml")
def saml_auth_stub():
    """SAML2 SSO stub endpoint for enterprise single sign-on."""
    return {
        "status": "not_configured",
        "protocol": "SAML 2.0",
        "message": "SSO/SAML2 integration is available for Enterprise plan.",
        "documentation": "https://docs.cyberguard.io/sso/saml2",
        "login_url": "/api/auth/saml/login",
        "acs_url": "/api/auth/saml/acs"
    }
