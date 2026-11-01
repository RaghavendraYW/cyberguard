"""
CyberGuard v3.0 — FastAPI Backend
Enterprise-grade cybersecurity risk management & Zero-Trust VPN platform.

Modular entrypoint — all logic is split into:
  config.py, database.py, schemas.py, auth.py, helpers.py, seed.py,
  scan.py, migrate_to_postgres.py, detection.py
  ml/ (anomaly, vendor, threat, insider, engine)
  routes/ (frontend, auth, dashboard, vendors, alerts, leaks, questionnaires,
           scan, logs, reports, admin, insider, monitoring, preferences,
           notifications, vpn, threat_detection)
"""
import os
import re
import time
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import structlog

from config import ALLOWED_ORIGINS, DEBUG, DATABASE_URL, FRONTEND_DIR, APP_NAME, VERSION
from database import DBSession
from seed import seed_db


def _mask_db_url(url: str) -> str:
    """Mask credentials in a database connection string for safe logging."""
    return re.sub(r'://([^:]+):([^@]+)@', r'://\1:***@', url)

# Import all route modules
from routes.frontend       import router as frontend_router
from routes.auth_routes    import router as auth_router
from routes.dashboard      import router as dashboard_router
from routes.vendors        import router as vendors_router
from routes.alerts         import router as alerts_router
from routes.leaks          import router as leaks_router
from routes.questionnaires import router as questionnaires_router
from routes.scan_routes    import router as scan_router
from routes.logs           import router as logs_router
from routes.reports        import router as reports_router
from routes.admin          import router as admin_router
from routes.insider        import router as insider_router
from routes.monitoring     import router as monitoring_router
from routes.preferences    import router as preferences_router
from routes.notifications  import router as notifications_router
from routes.vpn            import router as vpn_router
from routes.threat_detection import threat_router, posture_router

# ── Structured Logging (structlog) ────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(message)s",
)
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer() if not DEBUG else structlog.dev.ConsoleRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger("cyberguard")

# ── Rate Limiter ──────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── Lifespan & Scheduled Worker ───────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    db = DBSession()
    try:
        seed_db(db)
    except Exception as e:
        logger.error(f"Seed error (non-fatal): {e}")
    finally:
        db.close()

    # Scheduled reports background worker (weekly executive summary)
    async def scheduled_reports_worker():
        while True:
            try:
                from routes.reports import generate_weekly_executive_summary
                sched_db = DBSession()
                try:
                    generate_weekly_executive_summary(sched_db)
                finally:
                    sched_db.close()
            except Exception as ex:
                logger.warning(f"Scheduled report runner exception: {ex}")
            await asyncio.sleep(21600)  # Check every 6 hours

    scheduler_task = asyncio.create_task(scheduled_reports_worker())
    logger.info(f"[{APP_NAME}] v{VERSION} started - DEBUG={DEBUG}")
    try:
        yield
    finally:
        scheduler_task.cancel()
        logger.info(f"[{APP_NAME}] v{VERSION} shutting down")

# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title=f"{APP_NAME} API",
    version=VERSION,
    description="Enterprise-grade cybersecurity risk management platform.",
    docs_url="/docs"   if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
    lifespan=lifespan,
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Middleware ────────────────────────────────────────────────
_has_wildcard_origin = bool(ALLOWED_ORIGINS and "*" in ALLOWED_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else [],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=not _has_wildcard_origin,
)

# CSRF Protection & Security Headers
CSRF_EXEMPT_PATHS = {
    "/api/auth/login", "/api/auth/refresh", "/api/logs/track",
    "/api/monitoring/ingest",   # kept for backwards-compat (returns 404 gracefully)
    "/api/threats/ingest",      # agent event ingest
    "/api/threats/dns",         # DNS query check
    "/api/posture/report",      # device posture check
    "/api/vpn/mfa/verify",      # Zero-Trust MFA verification
    "/api/vpn/mfa/disconnect",  # MFA session disconnect
    "/health", "/api/health",
}

@app.middleware("http")
async def csrf_and_security_middleware(request: Request, call_next):
    """Enforce CSRF verification on mutating endpoints and add security headers."""
    # CSRF check
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        path = request.url.path
        if path.startswith("/api/") and path not in CSRF_EXEMPT_PATHS:
            has_csrf_header = bool(request.headers.get("x-requested-with"))
            has_auth_header = bool(request.headers.get("authorization"))
            if not (has_csrf_header or has_auth_header):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF verification failed: missing X-Requested-With or Authorization header"}
                )

    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 1)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Response-Time"] = f"{duration}ms"
    if not DEBUG:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ── Exception Handlers ────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# ── System Endpoints ──────────────────────────────────────────
@app.get("/health", tags=["system"])
def health_check():
    return {"status": "healthy", "version": VERSION, "app": APP_NAME}

# ── Static Files ──────────────────────────────────────────────
app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
app.mount("/js",  StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")),  name="js")

# ── Routers ───────────────────────────────────────────────────
app.include_router(frontend_router)
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(vendors_router)
app.include_router(alerts_router)
app.include_router(leaks_router)
app.include_router(questionnaires_router)
app.include_router(scan_router)
app.include_router(logs_router)
app.include_router(reports_router)
app.include_router(admin_router)
app.include_router(insider_router)
app.include_router(monitoring_router)
app.include_router(preferences_router)
app.include_router(notifications_router)
app.include_router(vpn_router)
app.include_router(threat_router)
app.include_router(posture_router)


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    print(f"\n{'='*60}")
    print(f"  [{APP_NAME}] v{VERSION} - Enterprise Security Platform")
    print(f"{'='*60}")
    print(f"  URL      : http://{host}:{port}")
    print(f"  Health   : http://{host}:{port}/health")
    print(f"  API Docs : {'http://'+host+':'+str(port)+'/docs' if DEBUG else 'disabled (set DEBUG=true)'}")
    print(f"  Database : {_mask_db_url(DATABASE_URL)[:60]}{'...' if len(DATABASE_URL)>60 else ''}")
    print(f"  Debug    : {DEBUG}")
    print(f"{'='*60}\n")
    uvicorn.run("main:app", host=host, port=port, reload=DEBUG, log_level="debug" if DEBUG else "info")
