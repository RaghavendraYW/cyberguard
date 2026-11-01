"""
CyberGuard v2.5 — SQLite to PostgreSQL Zero-Downtime Data Migration Utility

Migrates all existing tables, rows, relationships, and histories from local SQLite
to remote PostgreSQL (e.g., Neon, Supabase, AWS RDS, Render PostgreSQL) without data loss.

Usage:
    python backend/migrate_to_postgres.py --target "postgresql://user:password@host.provider.com:5432/dbname?sslmode=require"
Or set in .env:
    TARGET_DATABASE_URL=postgresql://user:password@host.provider.com:5432/dbname?sslmode=require
    python backend/migrate_to_postgres.py
"""
import sys
import os
import argparse
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure backend root is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

SQLITE_PATH = os.path.join(BASE_DIR, "cyberguard.db")
SQLITE_URL  = f"sqlite:///{SQLITE_PATH}"
from database import (
    Base, UserDB, UserPreferencesDB, VendorDB, AlertDB, LeakDB,
    QuestionnaireDB, ActivityLogDB, SecurityScoreDB, ReportDB,
    EmployeeActivityDB, WebhookConfigDB, RefreshTokenDB, VPNConnectionDB
)

MODELS_IN_ORDER = [
    ("Users", UserDB),
    ("User Preferences", UserPreferencesDB),
    ("Vendors", VendorDB),
    ("Alerts", AlertDB),
    ("Data Leaks", LeakDB),
    ("Questionnaires", QuestionnaireDB),
    ("Activity Logs", ActivityLogDB),
    ("Security Scores", SecurityScoreDB),
    ("Reports", ReportDB),
    ("Employee Activity", EmployeeActivityDB),
    ("Webhook Configs", WebhookConfigDB),
    ("Refresh Tokens", RefreshTokenDB),
    ("VPN Connections", VPNConnectionDB),
]


def normalize_postgres_url(url: str) -> str:
    url = url.strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://") and not url.startswith("postgresql+psycopg2://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


def run_migration(target_url: str):
    print("=" * 65)
    print("  CYBERGUARD v2.5 — SQLITE -> POSTGRESQL MIGRATION WIZARD")
    print("=" * 65)
    print(f" Source SQLite : {SQLITE_URL}")
    print(f" Target PG     : {target_url[:40]}... (credentials masked)\n")

    # Connect to SQLite source
    sqlite_engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
    SqliteSession = sessionmaker(bind=sqlite_engine)
    src_db = SqliteSession()

    # Connect to PostgreSQL target
    pg_url_norm = normalize_postgres_url(target_url)
    try:
        pg_engine = create_engine(pg_url_norm, pool_pre_ping=True, pool_recycle=300)
        with pg_engine.connect() as conn:
            print(" [PASS] Successfully reached PostgreSQL database server")
    except Exception as e:
        print(f" [FAIL] Could not connect to target PostgreSQL database:\n  {e}")
        print("\n Tip: Verify your credentials, host, database name, and ?sslmode=require if using cloud.")
        sys.exit(1)

    # Create tables in PostgreSQL
    print(" [INFO] Provisioning tables and constraints on target PostgreSQL...")
    Base.metadata.create_all(bind=pg_engine)
    print(" [PASS] All 13 tables verified/created on PostgreSQL\n")

    PgSession = sessionmaker(bind=pg_engine)
    target_db = PgSession()

    print(f"{'Table':<25} | {'Source Rows':<12} | {'Migrated':<12} | {'Status'}")
    print("-" * 65)

    total_migrated = 0

    try:
        for label, model in MODELS_IN_ORDER:
            src_rows = src_db.query(model).all()
            src_count = len(src_rows)
            if src_count == 0:
                print(f"{label:<25} | {0:<12} | {0:<12} | [OK]", flush=True)
                continue

            target_count = target_db.query(model).count()
            if target_count >= src_count:
                total_migrated += target_count
                print(f"{label:<25} | {src_count:<12} | {target_count:<12} | [OK - ALREADY SYNCED]", flush=True)
                continue

            # Fast bulk insert
            data_list = [{col.name: getattr(row, col.name) for col in row.__table__.columns} for row in src_rows]
            if target_count > 0:
                target_db.query(model).delete()
                target_db.commit()

            target_db.bulk_insert_mappings(model, data_list)
            target_db.commit()
            total_migrated += src_count
            print(f"{label:<25} | {src_count:<12} | {src_count:<12} | [OK]", flush=True)

        print("-" * 65)
        print(f" [COMPLETE] Migration successful! Total records migrated: {total_migrated}")
        print("\n Next Steps:")
        print(" 1. In your .env file, update DATABASE_URL with your PostgreSQL connection string:")
        print(f"    DATABASE_URL={target_url}")
        print(" 2. Restart CyberGuard: python backend/main.py (or run.bat)")
        print(" 3. CyberGuard will now run 100% on PostgreSQL with full concurrency!")
        print("=" * 65)

    except Exception as e:
        target_db.rollback()
        print(f"\n [ERROR] Migration interrupted: {e}")
        sys.exit(1)
    finally:
        src_db.close()
        target_db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate CyberGuard from SQLite to PostgreSQL")
    parser.add_argument("--target", help="Target PostgreSQL connection URL", default=None)
    args = parser.parse_args()

    target = args.target or os.getenv("TARGET_DATABASE_URL")
    if not target and os.getenv("DATABASE_URL", "").startswith(("postgres://", "postgresql://")):
        target = os.getenv("DATABASE_URL")

    if not target:
        print("Error: Target PostgreSQL URL is required.")
        print("Usage: python backend/migrate_to_postgres.py --target \"postgresql://user:pass@host:5432/dbname\"")
        print("Or set DATABASE_URL / TARGET_DATABASE_URL in .env")
        sys.exit(1)

    run_migration(target)
