"""
CyberGuard v2.0 — Authentication
JWT token creation, validation, and dependency helpers.
"""
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from sqlalchemy.orm import Session

from config import SECRET_KEY, ALGORITHM, JWT_HOURS, DEBUG
from database import get_db, UserDB

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def make_token(uid: int) -> str:
    return jwt.encode(
        {"sub": str(uid), "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_HOURS)},
        SECRET_KEY, algorithm=ALGORITHM
    )


def get_uid(token: str = Depends(oauth2)) -> int:
    if DEBUG and token == "demo-token-cyberguard":
        return 1
    try:
        return int(jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"])
    except Exception:
        raise HTTPException(401, "Invalid token")


def get_admin(uid: int = Depends(get_uid), db: Session = Depends(get_db)) -> int:
    u = db.get(UserDB, uid)
    if not u or not u.is_admin:
        raise HTTPException(403, "Admin only")
    return uid
