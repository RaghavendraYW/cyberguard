"""
CyberGuard v2.0 — Frontend & Health Routes
"""
import os
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from config import FRONTEND_DIR, DEBUG
from ml.engine import anomaly_detector, vendor_risk_scorer, threat_classifier

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def serve_index():
    path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(path):
        return HTMLResponse(f"<h2>index.html not found</h2><p>Looked in: {path}</p>", 404)
    with open(path, encoding="utf-8") as f:
        html = f.read()
    # Cache-busting versioning: dynamically inject file mtime
    try:
        mtime = int(os.path.getmtime(path))
        import re
        html = re.sub(r'\?v=[\d\.]+', f'?v={mtime}', html)
    except Exception:
        pass
    return HTMLResponse(html)


@router.get("/app", response_class=HTMLResponse)
def serve_app():
    return serve_index()


@router.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi import Response
    path = os.path.join(FRONTEND_DIR, "favicon.ico")
    if os.path.exists(path):
        from fastapi.responses import FileResponse
        return FileResponse(path)
    # Return 204 No Content if favicon doesn't exist to prevent 404 errors
    return Response(content=b"", status_code=204)


@router.get("/manifest.json", include_in_schema=False)
def manifest():
    from fastapi.responses import JSONResponse
    return JSONResponse({
        "name": "CyberGuard — Security Risk Platform",
        "short_name": "CyberGuard",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#07090f",
        "theme_color": "#07090f"
    })


@router.get("/health")
def health():
    path = os.path.join(FRONTEND_DIR, "index.html")
    return {
        "status": "ok",
        "app": os.getenv("APP_NAME", "CyberGuard"),
        "version": os.getenv("APP_VERSION", "2.0.0"),
        "frontend_exists": os.path.exists(path),
        "database": "connected",
        "ml": {
            "anomaly_detector":   {"status": "active" if anomaly_detector.trained   else "disabled"},
            "vendor_risk_scorer": {"status": "active" if vendor_risk_scorer.trained else "disabled"},
            "threat_classifier":  {"status": "active" if threat_classifier.trained  else "disabled"},
        }
    }


@router.get("/api/health")
def api_health():
    return {"status": "ok", "version": os.getenv("APP_VERSION", "2.0.0")}
