# Changelog — CyberGuard

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.5.0] — 2026-10-15

### ✨ Added
- **Zero-Trust WireGuard VPN Module** — Complete perimeter security module for managing enterprise WireGuard tunnels, peer configs, real-time handshake tracking, and client killswitch states.
- **WireGuard Configuration Provisioning** — Dynamic `.conf` file generator (`/api/vpn/config/{id}`) creating standard WireGuard client configs with pre-assigned virtual IPs (`10.8.0.0/24`) and DNS.
- **VPN Telemetry & Posture Engine** — Tracks connection state, live virtual IP, remote endpoint IP, latency (ms), sent/received transfer volumes, and device security compliance posture (`compliant`, `warning`, `failed`).
- **PostgreSQL Dual-Engine Support** — Full compatibility for both SQLite (local dev) and production PostgreSQL (Neon, Supabase, AWS RDS, Render) with automatic URL normalization (`postgres://` -> `postgresql+psycopg2://`).
- **PostgreSQL Connection Pooling** — Production-hardened SQLAlchemy pool settings: `pool_size=10`, `max_overflow=20`, `pool_recycle=300`, and `pool_pre_ping=True` to prevent idle connection termination.
- **Zero-Downtime Database Migration Tool** — `backend/migrate_to_postgres.py` migrating all 13 core relational tables and schemas from SQLite to target PostgreSQL in dependency-safe order.
- **WireGuard Network Hardening Guide** — Comprehensive deployment documentation (`docs/WIREGUARD_SETUP.md`) detailing Linux WireGuard gateway setup, UFW firewall isolation, and binding FastAPI to `10.8.0.1:8000`.
- **Perimeter UI Dashboard** — Dedicated frontend interface (`#page-vpn`) with live tunnel cards, status indicators, posture badges, connection killswitch toggle, and client provisioning modal.

### ♻ Changed
- **`config.py`** — Updated application version to `2.5.0`; added PostgreSQL URL normalization.
- **`database.py`** — Added `VPNConnectionDB` model with virtual IP, telemetry metrics, and posture fields; enhanced connection pooling for Postgres engines.
- **`main.py`** — Mounted `vpn_router` at `/api/vpn`; updated application version to `2.5.0`.
- **`seed.py`** — Added default VPN peer connections for standard enterprise identities.
- **`requirements.txt`** — Added `psycopg2-binary==2.9.9` driver for PostgreSQL support.

---

## [2.0.0] — 2026-09-19

### ✨ Added
- **Refresh Tokens** — Long-lived refresh tokens stored in DB with rotation on every use and revocation on logout
- **Rate Limiting** — `slowapi` 5 req/min on login, 60 req/min on telemetry ingest, 200 req/min default
- **Preferences API** — `GET /api/preferences` / `PUT /api/preferences` per-user notification, ML, and theme settings
- **Notifications API** — `GET /api/notifications/recent` notification feed + webhook CRUD with HMAC signing
- **PDF Export** — Reports downloadable as PDF via `reportlab` (`/api/reports/{id}/pdf`)
- **Pagination** — `skip` + `limit` query params on vendors, alerts, and reports list endpoints
- **Vendor SLA tracking** — `sla_days`, `last_review`, `next_review` fields on vendors
- **Alert Assignee** — Assign alerts to specific analyst email addresses
- **Notification center** — Bell dropdown polling every 30s for critical/high open alerts
- **Dark/light mode** — Toggle persisted to DB via preferences endpoint
- **Keyboard shortcuts** — GitHub-style `G+letter` navigation, `?` for shortcut overlay, `/` for search
- **Breadcrumbs** — Topbar breadcrumb updated on page navigation
- **Mobile responsive** — Collapsible sidebar overlay with touch-friendly toggle
- **Skeleton loaders** — Shimmer skeletons shown while data loads
- **`PaginationController`** — Reusable JS class for paginated table management
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `HSTS` (prod), `Referrer-Policy`
- **Webhook dispatch** — HMAC-signed outbound webhook delivery (fire-and-forget, async)
- **30-day score history** — Seed now seeds 30 days of score data (was 7 days)
- **SECURITY.md** — Vulnerability disclosure policy

### 🔧 Fixed
- **`datetime.utcnow()` deprecated** — Replaced all occurrences with `datetime.now(timezone.utc)` across all modules
- **Demo backdoor removed** — Eliminated the `demo-token-cyberguard` bypass in `auth.py`
- **Seed idempotency** — Seed now skips entirely if users already exist (was resetting passwords on every restart)
- **CORS misconfiguration** — `ALLOWED_ORIGINS` now warns loudly in prod when not set
- **`AlertDB.updated_at`** — `onupdate=_now` trigger now correctly set

### 🗑 Removed
- **"For college demonstration" label** — Replaced with collapsed "Developer Tools" section
- **Hardcoded login credentials** — Pre-filled email/password values removed from login form
- **Static BreachSight numbers** — Stats now derived from real API data (vendor count, alerts)
- **`EXAM_README.md`** — Academic artifact file deleted

### ♻ Changed
- **Seed passwords** — Strengthened to meet production password policy (`Admin@1234`, etc.)
- **API docs** — Disabled in production (`DEBUG=false`); only available when `DEBUG=true`
- **`config.py`** — Added SMTP, Webhook, rate limit, JWT refresh, and password policy settings
- **`database.py`** — Added `UserPreferencesDB`, `WebhookConfigDB`, `RefreshTokenDB` models; `pool_pre_ping=True` for PostgreSQL
- **`schemas.py`** — Added `max_length` validators, strong password enforcement, new schemas for all new features
- **`requirements.txt`** — Added `slowapi`, `httpx`, `reportlab`, `structlog`, `pydantic[email]`

---

## [1.0.0] — 2026-01-15

### Initial Release
- FastAPI backend with SQLite persistence
- JWT authentication
- Vendor risk management with ML scoring
- ML anomaly detection (Isolation Forest)
- Dark web leak monitoring
- Compliance questionnaire tracker
- Security score calculation
- Report generation
- Admin panel with activity logs
