# CyberGuard v2.0 Architecture

This document covers the high-level architecture, design decisions, and system boundaries of the CyberGuard platform.

## 1. Top-Level Architecture

CyberGuard operates on a monolithic **FastAPI Server** serving a **Vanilla JavaScript** frontend, with distributed **Endpoint Agents** feeding telemetry data to the backend via a REST API.

```
[ Employee Laptop ] --(Agent Telemetry)--> [ FastAPI Server ] <--(REST JSON)-- [ Dashboard UI ]
                                                   |
                                            (SQLite / PostgreSQL)
                                                   |
                                             (Scikit-Learn ML Engine)
```

## 2. Component Design Choices

### 2.1 Backend (FastAPI)
- Chosen for native async IO, auto-generating OpenAPI (`/docs`), and raw throughput.
- Strictly decoupled into domains (`routes/`, `ml/`, `schemas.py`, `database.py`).
- Security handles are baked into FastAPI `Depends()` pipelines ensuring guards are universally applied.

### 2.2 Agent Tracker (`agent/monitor.py`)
- Standard standard Python script leveraging `pygetwindow`.
- Configured using `--server` flags for flexible remote connections.
- Submits asynchronous `POST /ingest` logs over an interval-based loop to prevent server saturation.
- Authenticates uniquely via a server-generated `tracking_key` tied directly to an identity in the database.

### 2.3 Persistence (SQLAlchemy)
- Platform uses abstract ORM `SQLAlchemy`.
- Defaults to `SQLite` for simplicity during testing and development.
- Uses standard URI parameter connection mapping. Can transparently migrate to PostgreSQL by supplying `DATABASE_URL` during Render.com deployment.

### 2.4 ML Subsystem
- ML models are built with `scikit-learn` and stored using `joblib` for secure and fast disk-writing.
- **Isolation Forest**: Analyzes hour-of-entry, access-control logic, and volume of endpoint telemetry logs.
- **Random Forest**: Takes risk criteria heuristics for vendor metrics tracking.
- **Naive Bayes**: Classifies potential phishing payloads and malware identifiers.

## 3. Security Decisions

At v2.0, CyberGuard explicitly tackled production risks:
- Removed volatile Python `pickle.load()` invocations on physical binary payloads. Replaced natively with `joblib`.
- Defaulted insecure tokens and default configurations to behind `DEBUG` toggles.
- Addressed malicious telemetry ingestion through `html.escape` and rate-limiting safeguards.
- Enforced role checking via JWT payload validation (`get_admin` module).

## 4. Frontend Ecosystem
- Vanilla HTML/JS/CSS to bypass massive compilation overheads while maintaining deep control.
- Designed strictly adhering to modern CSS parameters (grid templating, color tokens, fluid animations, responsive layouts).
- Relies on `Chart.js` for data visualization.
