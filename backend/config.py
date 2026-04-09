"""
CyberGuard v2.0 — Configuration
Environment variables, paths, constants.
"""
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
ML_DIR       = os.path.join(BASE_DIR, "ml", "saved_models")
os.makedirs(ML_DIR, exist_ok=True)

SECRET_KEY      = os.getenv("SECRET_KEY", "cyberguard-fallback-secret-change-me")
ALGORITHM       = "HS256"
JWT_HOURS       = int(os.getenv("JWT_EXPIRE_HOURS", "12"))
DATABASE_URL    = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'cyberguard.db')}")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
DEBUG           = os.getenv("DEBUG", "false").lower() == "true"
