"""
CyberGuard v2.0 — FastAPI Backend
Full-stack cybersecurity risk management platform.

Modular entrypoint — all logic is split into:
  config.py, database.py, schemas.py, auth.py, helpers.py, seed.py, scan.py
  ml/ (anomaly, vendor, threat, insider, engine)
  routes/ (frontend, auth, dashboard, vendors, alerts, leaks, questionnaires, scan, logs, reports, admin, insider)
"""
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import ALLOWED_ORIGINS, DEBUG, DATABASE_URL, FRONTEND_DIR
from database import DBSession
from seed import seed_db

# Import all route modules
from routes.frontend import router as frontend_router
from routes.auth_routes import router as auth_router
from routes.dashboard import router as dashboard_router
from routes.vendors import router as vendors_router
from routes.alerts import router as alerts_router
from routes.leaks import router as leaks_router
from routes.questionnaires import router as questionnaires_router
from routes.scan_routes import router as scan_router
from routes.logs import router as logs_router
from routes.reports import router as reports_router
from routes.admin import router as admin_router
from routes.insider import router as insider_router
from routes.monitoring import router as monitoring_router

# ══════════════════════════════════════════════════════════════
# APP
# ══════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    db = DBSession()
    try:
        seed_db(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title="CyberGuard API",
    version="2.0.0",
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

@app.get("/health", tags=["system"])
def health_check():
    return {"status": "healthy", "version": "2.0.0"}

# Mount static files for CSS/JS
app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")

# Include all routers
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




if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    print(f"\n{'='*55}")
    print(f"  * CyberGuard v2.0 - Production Ready")
    print(f"{'='*55}")
    print(f"  URL      : http://{host}:{port}")
    print(f"  Health   : http://{host}:{port}/health")
    print(f"  Docs     : {'http://'+host+':'+str(port)+'/docs' if DEBUG else 'disabled (set DEBUG=true)'}")
    print(f"  Frontend : {FRONTEND_DIR}")
    print(f"  Database : {DATABASE_URL[:40]}...")
    print(f"  Debug    : {DEBUG}")
    print(f"{'='*55}\n")
    uvicorn.run("main:app", host=host, port=port, reload=DEBUG)
