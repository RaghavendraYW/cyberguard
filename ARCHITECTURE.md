# CyberGuard v2.5 Architecture

This document covers the high-level architecture, design decisions, and system boundaries of the CyberGuard platform.

## 1. Top-Level Architecture

CyberGuard operates as an enterprise-grade secure platform combining a **FastAPI Backend Server**, a **Zero-Trust WireGuard VPN Gateway**, a **Vanilla JavaScript SPA Frontend**, and distributed **Endpoint Telemetry Agents**.

```
                           [ Public Internet ]
                                    │
                                    ▼ UDP: 51820 (WireGuard Only)
                      ┌───────────────────────────┐
                      │  WireGuard Gateway (wg0)  │
                      │       10.8.0.1/24         │
                      └─────────────┬─────────────┘
                                    │ Encrypted ChaCha20 Tunnels
         ┌──────────────────────────┴──────────────────────────┐
         ▼                                                     ▼
[ Admin / Analyst UI ]                                [ Employee Laptop ]
IP: 10.8.0.2                                          IP: 10.8.0.3
Posture: Compliant                                    Agent Telemetry
         │                                                     │
         └──────────────────────────┬──────────────────────────┘
                                    ▼ (HTTP strictly over 10.8.0.1:8000)
                         ┌───────────────────────┐
                         │    FastAPI Server     │
                         └──────────┬────────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 ▼                                     ▼
      [ PostgreSQL / SQLite ]              [ Scikit-Learn ML Engine ]
      • Connection Pooling (10+20)         • Isolation Forest (Anomaly)
      • Recycle (300s) + Pre-ping          • Random Forest (Vendor Risk)
      • Zero-Downtime Migration            • Heuristic Classifier
```

## 2. Component Design Choices

### 2.1 Backend (FastAPI)
- Native async I/O, auto-generating OpenAPI (`/docs`), and high throughput.
- Modular domain routes (`routes/`, `ml/`, `schemas.py`, `database.py`).
- Security handles baked into FastAPI `Depends()` pipelines for universal policy enforcement.

### 2.2 Agent Tracker (`agent/monitor.py`)
- Cross-platform agent leveraging `pygetwindow`.
- Configured with `--server` flags for flexible remote connections over VPN.
- Submits asynchronous `POST /ingest` logs over an interval-based loop to prevent server saturation.
- Authenticates uniquely via a server-generated `tracking_key` tied to an identity in the database.

### 2.3 Persistence (SQLAlchemy & PostgreSQL Dual-Engine)
- **Dual Engine**: Seamless operation on SQLite for local development and PostgreSQL (Neon, Supabase, AWS RDS, Render) in production.
- **Connection Pool Hardening**: `pool_size=10`, `max_overflow=20`, `pool_recycle=300`, and `pool_pre_ping=True` prevent stale connection drops on serverless/cloud Postgres hosts.
- **Scheme Normalization**: Transparently maps legacy `postgres://` URLs to `postgresql+psycopg2://`.
- **Zero-Downtime Migration Tool**: `backend/migrate_to_postgres.py` transfers all 13 relational tables from SQLite to PostgreSQL with integrity checks.

### 2.4 ML Subsystem
- ML models built with `scikit-learn` and persisted using `joblib`.
- **Isolation Forest**: Analyzes hour-of-entry, access-control logic, and volume of endpoint telemetry logs.
- **Random Forest**: Takes risk criteria heuristics for vendor metrics tracking.
- **Naive Bayes**: Classifies potential phishing payloads and malware identifiers.

### 2.5 Zero-Trust Perimeter & WireGuard VPN Architecture
- **Network Perimeter Isolation**: Binds internal FastAPI listening sockets to the private WireGuard gateway interface (`10.8.0.1:8000`), blocking unauthorized public WAN access.
- **Client Configuration Provisioning**: Dynamic `.conf` generator (`/api/vpn/config/{id}`) formats ChaCha20-Poly1305 credentials, virtual IP assignments (`10.8.0.x`), and gateway endpoints.
- **Continuous Posture Checks**: Real-time evaluation of device security compliance (`compliant`, `warning`, `failed`) and immediate killswitch toggling.

## 3. Security Decisions

CyberGuard v2.5 implements multi-layer defense-in-depth:
- **Zero Public Port Exposure**: Only WireGuard UDP 51820 is publicly accessible; application ports are firewalled via UFW.
- **Safe Serialization**: `joblib` replaces volatile Python `pickle.load()` on disk payloads.
- **Production Guardrails**: Insecure demo bypass tokens and debug endpoints disabled when `DEBUG=false`.
- **Rate-Limiting**: `slowapi` protects against brute-force attacks on authentication (5 req/min) and ingestion (60 req/min).
- **Session Security**: Short-lived JWT access tokens paired with rotating, revocable database-backed refresh tokens.

## 4. Frontend Ecosystem
- Vanilla HTML/JS/CSS eliminating compilation overhead while maintaining total control.
- Modern CSS variables, glassmorphic design system, responsive drawer, and dark/light modes.
- Interactive visualizations powered by `Chart.js`.

