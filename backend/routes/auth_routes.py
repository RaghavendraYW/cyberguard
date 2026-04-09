"""
CyberGuard v2.0 — Auth Routes
"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db, UserDB, ActivityLogDB
from schemas import LoginReq, ProfileUpdate
from auth import make_token, get_uid, oauth2
from helpers import udict, get_ip, get_device

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
def login(req: LoginReq, request: Request, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter_by(email=req.email.lower().strip()).first()
    if not user or not check_password_hash(user.password_hash, req.password):
        raise HTTPException(401, "Invalid credentials")
    user.last_seen = datetime.utcnow()
    ip = get_ip(request)
    ua = request.headers.get("user-agent", "")
    device = get_device(ua)
    db.add(ActivityLogDB(user_email=user.email, action="login", ip_address=ip, user_agent=ua[:300], device_info=device, page="login"))
    db.commit()
    return {"token": make_token(user.id), "user": udict(user)}


@router.post("/token")
def token_form(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter_by(email=form.username).first()
    if not user or not check_password_hash(user.password_hash, form.password):
        raise HTTPException(401, "Invalid")
    return {"access_token": make_token(user.id), "token_type": "bearer"}


@router.get("/me")
def me(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    u = db.get(UserDB, uid)
    if not u:
        raise HTTPException(404)
    return udict(u)


@router.put("/update")
def update_profile(req: ProfileUpdate, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    u = db.get(UserDB, uid)
    for f in ["name", "role", "company", "domain"]:
        v = getattr(req, f)
        if v is not None:
            setattr(u, f, v)
    if req.password:
        u.password_hash = generate_password_hash(req.password)
    db.commit()
    return udict(u)
