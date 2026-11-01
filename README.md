# 🛡 CyberGuard v2.5 — Enterprise Security Risk & Zero-Trust Platform

CyberGuard is a **production-ready, enterprise-grade** cybersecurity risk management and perimeter security platform. It provides unified vendor risk scoring, Zero-Trust WireGuard VPN access, AI/ML-powered anomaly detection, dark web breach monitoring, compliance management, and real-time threat intelligence — all in a single self-hosted dashboard.

## ✨ Key Features

| Module | Description |
|---|---|
| **Zero-Trust VPN** | Encrypted WireGuard perimeter tunnels, dynamic client `.conf` provisioning, live peer telemetry, posture validation, and remote killswitch |
| **PostgreSQL Dual-Engine** | Native SQLite + PostgreSQL dual compatibility with pooling (`pool_recycle=300`), auto-reconnect (`pool_pre_ping`), and zero-downtime migration utility |
| **Security Score** | Composite risk score (0–950) updated in real-time based on alerts, vendor health, leaks, and ML anomalies |
| **Vendor Risk** | Automated domain scanning, ML-powered risk classification (Low/Medium/High/Critical), SLA tracking |
| **Alerts** | Multi-severity alert management with ML-based auto-classification and assignee tracking |
| **Data Leaks** | Dark web credential leak monitoring with investigation workflow |
| **ML Anomalies** | Isolation Forest anomaly detection on user activity logs (after-hours logins, unusual IPs, etc.) |
| **Insider Detection** | Real-time employee activity monitoring with ML scoring |
| **Compliance** | SOC 2, ISO 27001, GDPR, NIST CSF, PCI DSS, HIPAA questionnaire tracker |
| **Reports** | Generate security posture, vendor risk, executive summary, incident, and compliance reports with PDF export |
| **Notifications** | Bell dropdown, webhook dispatch (Slack/Teams/PagerDuty) with HMAC signing |
| **Admin** | User management, activity audit logs, online user tracking, CSV export |

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone <repo-url>
cd CyberGuard_Final_App
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | JWT signing secret (REQUIRED in production) | Random (ephemeral) |
| `DATABASE_URL` | SQLAlchemy URL | `sqlite:///backend/cyberguard.db` |
| `DEBUG` | Enable debug mode & API docs | `false` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | Empty (same-origin only) |
| `JWT_EXPIRE_HOURS` | Access token lifetime | `2` |
| `JWT_REFRESH_DAYS` | Refresh token lifetime | `30` |
| `SMTP_HOST` | SMTP server for email alerts | `` |
| `SMTP_USER` | SMTP username | `` |
| `SMTP_PASSWORD` | SMTP password | `` |
| `WEBHOOK_URL` | Slack/Teams/PagerDuty webhook URL | `` |
| `RATE_LIMIT_LOGIN` | Login rate limit | `5/minute` |

### 3. Run

```bash
cd backend
python main.py
```

The platform is now running at **http://localhost:8000**

**Default login credentials** (seeded on first run):

| User | Email | Password | Role |
|---|---|---|---|
| Alex Kumar | admin@company.com | Admin@1234 | CISO (Admin) |
| Priya Sharma | priya@company.com | Analyst@1234 | Security Analyst |
| Rahul Verma | rahul@company.com | Devops@1234 | DevOps Engineer |

## 🏗 Architecture

```
CyberGuard_Final_App/
├── backend/
│   ├── main.py                 # FastAPI app, middleware, routing
│   ├── config.py               # Environment variables & DB URL normalization
│   ├── database.py             # SQLAlchemy models & connection pooling
│   ├── auth.py                 # JWT auth + refresh tokens
│   ├── schemas.py              # Pydantic request/response models
│   ├── helpers.py              # Scoring, serialization, IP detection
│   ├── seed.py                 # Idempotent database seeder
│   ├── scan.py                 # Domain scanning
│   ├── migrate_to_postgres.py  # SQLite to PostgreSQL zero-downtime migration
│   ├── ml/                     # Machine learning models & engine
│   └── routes/                 # API route handlers
│       ├── auth_routes.py      # Login, refresh, logout, profile
│       ├── dashboard.py        # Score, badges, activity feed
│       ├── vpn.py              # Zero-Trust WireGuard VPN management & .conf generator
│       ├── vendors.py          # Vendor CRUD + scanning
│       ├── alerts.py           # Alert management + ML classify
│       ├── leaks.py            # Data leak monitoring
│       ├── logs.py             # Activity logs + anomaly detection
│       ├── reports.py          # Report generation + PDF export
│       ├── admin.py            # Admin panel (users, stats)
│       ├── monitoring.py       # Employee monitoring + telemetry
│       ├── insider.py          # Insider threat detection
│       ├── notifications.py    # Webhook CRUD + notification feed
│       └── preferences.py      # Per-user UI/notification prefs
├── frontend/
│   ├── index.html              # Single-page application UI
│   ├── css/
│   │   ├── styles.css          # Core design system
│   │   └── enterprise.css       # Enterprise extensions
│   └── js/
│       ├── main.js             # Bootstrap & session management
│       ├── sidebar.js          # Navigation, breadcrumbs, mobile menu
│       ├── vpn.js              # Zero-Trust WireGuard monitoring & config download
│       ├── notifications.js    # Bell dropdown, theme toggle, pagination
│       ├── keyboard.js         # GitHub-style keyboard shortcuts
│       ├── settings.js         # Settings + preferences persistence
│       └── ...                 # Feature-specific modules
├── docs/
│   └── WIREGUARD_SETUP.md      # Zero-Trust WireGuard gateway & UFW lockdown guide
└── requirements.txt
```

## 🛡️ Zero-Trust WireGuard VPN & Network Isolation

CyberGuard v2.5 can be strictly locked down behind an encrypted WireGuard VPN tunnel (`10.8.0.0/24`), isolating all management endpoints from the public internet:
- **WireGuard Setup Guide**: Follow [docs/WIREGUARD_SETUP.md](docs/WIREGUARD_SETUP.md) to configure the Linux gateway and apply UFW isolation rules.
- **Client Configuration Provisioning**: Download auto-generated `.conf` files directly from the dashboard (`#page-vpn`) or via `/api/vpn/config/{id}`.
- **Posture & Killswitch Control**: Enforce device compliance and toggle peer access in real time.

## 🗄️ Database Migration (SQLite ➔ PostgreSQL)

To migrate an existing SQLite database to a cloud-hosted PostgreSQL instance (Neon, Supabase, Render, AWS RDS) with zero data loss:

```bash
# Direct command line execution
python backend/migrate_to_postgres.py --target "postgresql://user:password@host:5432/dbname?sslmode=require"

# Or configure via environment variable in .env
TARGET_DATABASE_URL=postgresql://user:password@host:5432/dbname?sslmode=require
python backend/migrate_to_postgres.py
```
This migrates all 13 relational tables and indices with dependency ordering and data verification.

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `G` then `D` | Go to Dashboard |
| `G` then `V` | Go to Vendor Risk |
| `G` then `A` | Go to Alerts |
| `G` then `R` | Go to Reports |
| `G` then `S` | Go to Settings |
| `/` | Focus search |
| `?` | Show all shortcuts |
| `Esc` | Close modal |

## 🔒 Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## 🚢 Production Deployment Checklist

- [ ] Set a strong `SECRET_KEY` in environment
- [ ] Set `DEBUG=false`
- [ ] Set `ALLOWED_ORIGINS=https://yourdomain.com`
- [ ] Use PostgreSQL: `DATABASE_URL=postgresql://...`
- [ ] Put behind a reverse proxy (nginx/Caddy) with TLS
- [ ] Configure SMTP for email alerts
- [ ] Configure webhook URL for Slack/Teams alerts
- [ ] Set up backups for the database
- [ ] Review and rotate seed passwords immediately
- [ ] Enable HSTS on the reverse proxy

## 📄 License

Proprietary — All rights reserved.
