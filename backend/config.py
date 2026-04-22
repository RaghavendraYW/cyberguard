"""
CyberGuard v2.0 — Configuration
Environment variables, paths, constants.
"""
import os
import secrets
import logging
from dotenv import load_dotenv

load_dotenv()

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
ML_DIR       = os.path.join(BASE_DIR, "ml", "saved_models")
os.makedirs(ML_DIR, exist_ok=True)

DEBUG           = os.getenv("DEBUG", "false").lower() == "true"

_secret = os.getenv("SECRET_KEY")
if not _secret:
    if not DEBUG:
        logging.warning("CRITICAL: SECRET_KEY not set in production! Generating random ephemeral key.")
    SECRET_KEY = secrets.token_hex(32)
else:
    SECRET_KEY = _secret

ALGORITHM       = "HS256"
JWT_HOURS       = int(os.getenv("JWT_EXPIRE_HOURS", "12"))
DATABASE_URL    = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'cyberguard.db')}")

_origins = os.getenv("ALLOWED_ORIGINS")
if _origins:
    ALLOWED_ORIGINS = _origins.split(",")
else:
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"] if DEBUG else []
