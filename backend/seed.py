"""
CyberGuard v2.0 — Database Seed
Initial data population for demo/development.
"""
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

from database import (
    UserDB, VendorDB, AlertDB, LeakDB, QuestionnaireDB,
    ActivityLogDB, SecurityScoreDB
)
from helpers import grade


def seed_db(db):
    users_data = [
        dict(name="Alex Kumar",   email="admin@company.com", password_hash=generate_password_hash("password"),    role="Security Analyst", is_admin=True),
        dict(name="Priya Sharma", email="priya@company.com", password_hash=generate_password_hash("password123"), role="IT Analyst",        is_admin=False),
        dict(name="Rahul Verma",  email="rahul@company.com", password_hash=generate_password_hash("password123"), role="DevOps Engineer",   is_admin=False),
        dict(name="Sara Khan",    email="sara@company.com",  password_hash=generate_password_hash("password123"), role="Security Engineer",  is_admin=False),
        dict(name="James Wilson", email="james@company.com", password_hash=generate_password_hash("password123"), role="Network Admin",      is_admin=False),
    ]

    for u_data in users_data:
        existing_user = db.query(UserDB).filter_by(email=u_data["email"]).first()
        if existing_user:
            existing_user.password_hash = u_data["password_hash"]
            existing_user.is_admin = u_data["is_admin"]
            existing_user.role = u_data["role"]
        else:
            db.add(UserDB(**u_data))
    
    if db.query(VendorDB).first():
        db.commit()
        return

    for v in [
        dict(name="Salesforce",   domain="salesforce.com",  category="CRM",                 criticality="Critical", score=880, issues=2,  status="monitored", trend="+5"),
        dict(name="AWS",          domain="aws.amazon.com",  category="Cloud Infrastructure", criticality="Critical", score=912, issues=1,  status="monitored", trend="+2"),
        dict(name="CloudHostPro", domain="cloudhostpro.io", category="Cloud Infrastructure", criticality="High",     score=540, issues=18, status="review",    trend="-42"),
        dict(name="Slack",        domain="slack.com",       category="Communication",        criticality="High",     score=820, issues=5,  status="monitored", trend="-8"),
        dict(name="Stripe",       domain="stripe.com",      category="Payment Processing",   criticality="Critical", score=930, issues=1,  status="monitored", trend="+7"),
        dict(name="Zoom",         domain="zoom.us",         category="Communication",        criticality="Medium",   score=690, issues=11, status="review",    trend="-15"),
    ]:
        db.add(VendorDB(**v))

    for a in [
        dict(title="SSL Certificate expiring in 7 days",    severity="critical", category="Website Security", status="open",         description="api.acmecorp.com SSL cert expires soon."),
        dict(title="Admin panel exposed to public internet", severity="critical", category="Network",          status="open",         description="admin.acmecorp.com is publicly accessible."),
        dict(title="Vendor score dropped 42 points",        severity="high",     category="Vendor Risk",       status="open",         description="CloudHostPro score dropped significantly."),
        dict(title="DMARC policy not enforced",             severity="high",     category="Email Security",    status="acknowledged", description="DMARC policy is in p=none mode."),
        dict(title="New credential leak detected",          severity="critical", category="Data Leak",         status="open",         description="2 employee credentials found on dark web."),
    ]:
        db.add(AlertDB(**a))

    for l in [
        dict(title="Corporate credentials on BreachForums", severity="critical", source="Dark Web",   credentials=2, records=0, status="investigating", details="Employee credentials found in breach dump."),
        dict(title="API keys found on Pastebin",            severity="high",     source="Paste Site", credentials=0, records=0, status="open",          details="Internal API keys exposed publicly."),
    ]:
        db.add(LeakDB(**l))

    for q in [
        dict(title="SOC 2 Type II Assessment", framework="SOC 2",     vendor="CloudHostPro", total=21, answered=15, status="in_progress", due_date="2026-04-20"),
        dict(title="GDPR Compliance Review",    framework="GDPR",      vendor="",             total=11, answered=11, status="completed",   due_date="2026-02-28"),
        dict(title="ISO 27001 Gap Analysis",    framework="ISO 27001", vendor="AWS",          total=30, answered=8,  status="in_progress", due_date="2026-05-15"),
        dict(title="NIST CSF Assessment",       framework="NIST CSF",  vendor="",             total=23, answered=14, status="in_progress", due_date="2026-06-01"),
        dict(title="PCI DSS v4.0 Audit",        framework="PCI DSS",   vendor="Stripe",       total=15, answered=6,  status="in_progress", due_date="2026-05-30"),
        dict(title="HIPAA Security Review",     framework="HIPAA",     vendor="",             total=18, answered=12, status="in_progress", due_date="2026-07-01"),
    ]:
        db.add(QuestionnaireDB(**q))

    # Seed 7 days of score history
    base = 742
    for days_ago in range(6, -1, -1):
        s = max(100, min(950, base + random.randint(-15, 15)))
        ts = datetime.utcnow() - timedelta(days=days_ago)
        db.add(SecurityScoreDB(score=s, grade=grade(s), created_at=ts))
        base = s

    # Seed 300 activity logs
    users_emails = ["admin@company.com", "priya@company.com", "rahul@company.com", "sara@company.com", "james@company.com"]
    acts = ["login", "view_dashboard", "export_report", "add_vendor", "scan_domain", "access_settings", "view_vendor", "update_alert"]
    devices = ["Windows PC", "MacBook", "Linux", "Windows PC", "Windows PC"]
    for i in range(300):
        hour = random.randint(8, 20) if random.random() > 0.05 else random.randint(1, 5)
        ts = datetime.utcnow() - timedelta(days=random.randint(0, 30))
        ts = ts.replace(hour=hour, minute=random.randint(0, 59))
        uidx = random.randint(0, 4)
        db.add(ActivityLogDB(
            user_email=users_emails[uidx], action=random.choice(acts),
            ip_address=f"192.168.1.{random.randint(1, 80)}", device_info=devices[uidx],
            timestamp=ts, is_anomaly=(hour < 6),
            anomaly_score=(0.92 if hour < 6 else round(random.uniform(0.1, 0.4), 2))
        ))

    db.commit()
    print("✅ Database seeded with 5 users, 6 vendors, 5 alerts, 2 leaks, 6 questionnaires, 300 activity logs")
