"""
CyberGuard v2.5 — Configuration
Environment variables, paths, and constants for all deployment stages.
"""
import os
import secrets
import logging
from dotenv import load_dotenv

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
ML_DIR       = os.path.join(BASE_DIR, "ml", "saved_models")
os.makedirs(ML_DIR, exist_ok=True)

# Load .env from backend/ or parent directory
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(BASE_DIR, "..", ".env"))

# ── Core ──────────────────────────────────────────────────────
DEBUG    = os.getenv("DEBUG", "false").lower() == "true"
APP_NAME = "CyberGuard"
VERSION  = "2.5.0"

# ── Security ──────────────────────────────────────────────────
_secret = os.getenv("SECRET_KEY")
if not _secret:
    if not DEBUG:
        logging.warning(
            "CRITICAL: SECRET_KEY not set in production! "
            "Generating random ephemeral key — tokens will invalidate on restart."
        )
    SECRET_KEY = secrets.token_hex(32)
else:
    SECRET_KEY = _secret

ALGORITHM             = "HS256"
JWT_HOURS             = int(os.getenv("JWT_EXPIRE_HOURS", "2"))          # short-lived access token
JWT_REFRESH_DAYS      = int(os.getenv("JWT_REFRESH_DAYS", "30"))         # long-lived refresh token
MAX_LOGIN_ATTEMPTS    = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))        # per minute per IP
PASSWORD_MIN_LENGTH   = int(os.getenv("PASSWORD_MIN_LENGTH", "8"))

# ── Database ──────────────────────────────────────────────────
_raw_db_url = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'cyberguard.db')}"
)
# Normalization for modern cloud hosts (Render / Heroku / Supabase / Neon often use postgres://)
if _raw_db_url.startswith("postgres://"):
    DATABASE_URL = _raw_db_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif _raw_db_url.startswith("postgresql://") and not _raw_db_url.startswith("postgresql+psycopg2://"):
    DATABASE_URL = _raw_db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
else:
    DATABASE_URL = _raw_db_url


# ── CORS ──────────────────────────────────────────────────────
_origins = os.getenv("ALLOWED_ORIGINS")
if _origins:
    ALLOWED_ORIGINS = [o.strip() for o in _origins.split(",") if o.strip()]
elif DEBUG:
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000",
                       "http://localhost:8000", "http://127.0.0.1:8000"]
else:
    # In production, ALLOWED_ORIGINS env var is mandatory.
    # Warn loudly if not set; the app will still serve same-origin requests.
    logging.warning(
        "ALLOWED_ORIGINS not set in production — cross-origin requests will be blocked. "
        "Set ALLOWED_ORIGINS=https://yourdomain.com in environment."
    )
    ALLOWED_ORIGINS = []

# ── Email (SMTP) ───────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "alerts@cyberguard.io")
EMAIL_ENABLED = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)

# ── Webhooks ───────────────────────────────────────────────────
WEBHOOK_URL     = os.getenv("WEBHOOK_URL", "")       # Slack / Teams / PagerDuty URL
WEBHOOK_SECRET  = os.getenv("WEBHOOK_SECRET", "")    # HMAC signing secret
WEBHOOK_ENABLED = bool(WEBHOOK_URL)

# ── Rate Limiting ─────────────────────────────────────────────
RATE_LIMIT_LOGIN   = os.getenv("RATE_LIMIT_LOGIN",   "120/minute")
RATE_LIMIT_INGEST  = os.getenv("RATE_LIMIT_INGEST",  "120/minute")
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "200/minute")
