# Memo: PostgreSQL & VPN Implementation Details

### Database (PostgreSQL & SQLite)
- **Driver**: `psycopg2-binary==2.9.9` in `requirements.txt`.
- **URL normalization**: `backend/config.py` maps `postgres://` -> `postgresql+psycopg2://`.
- **Pool settings**: `backend/database.py` configured with `pool_size=10, max_overflow=20, pool_recycle=300, pool_pre_ping=True`.
- **Migration script**: `backend/migrate_to_postgres.py` for zero-downtime transfer from SQLite to PostgreSQL.
- **Config examples**: `.env.example` updated with free-tier providers (Neon / Supabase).

### Zero-Trust VPN Module
- **ORM Model**: `VPNConnectionDB` in `backend/database.py` (L208-228).
- **Routes**: `backend/routes/vpn.py` mounted in `backend/main.py`.
  - `/api/vpn/status`
  - `/api/vpn/connections`
  - `/api/vpn/toggle/{id}`
  - `/api/vpn/posture/{id}`
  - `/api/vpn/config/{id}`
- **Frontend**:
  - `frontend/index.html`: Added Perimeter & Network nav + `#page-vpn` dashboard + WireGuard modals.
  - `frontend/js/sidebar.js`: Routed `vpn` page.
  - `frontend/js/vpn.js`: Handlers for telemetry, filters, connection toggling, and `.conf` file downloads.
- **Deployment guide**: `docs/WIREGUARD_SETUP.md` with WireGuard gateway & UFW firewall rules.
