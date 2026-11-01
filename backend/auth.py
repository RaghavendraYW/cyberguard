"""
CyberGuard v2.0 — Authentication
JWT access + refresh token creation, validation, and dependency helpers.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from config import SECRET_KEY, ALGORITHM, JWT_HOURS, JWT_REFRESH_DAYS
from database import get_db, UserDB, RefreshTokenDB

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

_REFRESH_SECRET = SECRET_KEY + "_refresh"   # separate secret for refresh tokens


import secrets


# ── Token Creation ────────────────────────────────────────────
def make_token(uid: int) -> str:
    """Create a short-lived JWT access token."""
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_HOURS)
    return jwt.encode({"sub": str(uid), "exp": exp, "type": "access", "jti": secrets.token_hex(16)}, SECRET_KEY, algorithm=ALGORITHM)


def make_refresh_token(uid: int) -> str:
    """Create a long-lived opaque-style JWT refresh token."""
    exp = datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_DAYS)
    return jwt.encode({"sub": str(uid), "exp": exp, "type": "refresh", "jti": secrets.token_hex(16)}, _REFRESH_SECRET, algorithm=ALGORITHM)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def store_refresh_token(uid: int, token: str, db: Session) -> None:
    """Persist a refresh token hash for revocation tracking."""
    expires = datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_DAYS)
    h = _hash_token(token)
    existing = db.query(RefreshTokenDB).filter_by(token_hash=h).first()
    if existing:
        existing.revoked = False
        existing.expires_at = expires
    else:
        db.add(RefreshTokenDB(
            user_id=uid,
            token_hash=h,
            expires_at=expires
        ))
    try:
        db.commit()
    except Exception:
        db.rollback()


def revoke_refresh_token(token: str, db: Session) -> None:
    """Mark a refresh token as revoked."""
    h = _hash_token(token)
    rt = db.query(RefreshTokenDB).filter_by(token_hash=h).first()
    if rt:
        rt.revoked = True
        db.commit()


def validate_refresh_token(token: str, db: Session) -> int:
    """Validate a refresh token and return the user ID. Raises 401 on failure."""
    try:
        payload = jwt.decode(token, _REFRESH_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")
        uid = int(payload["sub"])
    except JWTError:
        raise HTTPException(401, "Invalid or expired refresh token")

    h = _hash_token(token)
    rt = db.query(RefreshTokenDB).filter_by(token_hash=h).first()
    if not rt or rt.revoked:
        raise HTTPException(401, "Refresh token revoked or expired")
    exp = rt.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(401, "Refresh token revoked or expired")
    return uid


# ── Request Dependencies ──────────────────────────────────────
def get_uid(token: str = Depends(oauth2)) -> int:
    """Extract and validate the user ID from a JWT access token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(401, "Invalid token type")
        return int(payload["sub"])
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")


# ── RBAC Roles ────────────────────────────────────────────────
# Role hierarchy: admin > ciso > analyst > viewer
RBAC_WRITE_ROLES = {"admin", "ciso", "analyst", "Admin", "CISO", "Analyst", "Security Analyst", "IT Analyst"}
RBAC_ADMIN_ROLES = {"admin", "Admin"}


def get_admin(uid: int = Depends(get_uid), db: Session = Depends(get_db)) -> int:
    u = db.get(UserDB, uid)
    if not u or not u.is_admin:
        raise HTTPException(403, "Admin access required")
    return uid


def get_analyst(uid: int = Depends(get_uid), db: Session = Depends(get_db)) -> int:
    """Require at least analyst-level role (admin, ciso, or analyst). Viewers are blocked."""
    u = db.get(UserDB, uid)
    if not u:
        raise HTTPException(404, "User not found")
    if u.is_admin or u.role in RBAC_WRITE_ROLES or (u.role and any(r in u.role.lower() for r in ("admin", "ciso", "analyst", "seceng", "security"))):
        return uid
    raise HTTPException(403, "Analyst-level access required. Viewers cannot perform this action.")


def get_current_user(uid: int = Depends(get_uid), db: Session = Depends(get_db)) -> UserDB:
    u = db.get(UserDB, uid)
    if not u:
        raise HTTPException(404, "User not found")
    return u
