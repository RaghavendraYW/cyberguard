# 🛡 CyberGuard v2.0 — Cybersecurity Risk Management Platform

A production-ready, full-stack cybersecurity risk management platform with real-time multi-user monitoring, ML-powered threat detection, and vendor risk assessment.

**Live Demo:** [Deploy to Render →](#deploy-to-render-free)

---

## ✨ Features

### Security Dashboard
- Real-time security score (0–950) with grade
- Risk trend charts and donut charts
- ML model status monitoring

### Vendor Risk Management
- Track unlimited third-party vendors
- ML-powered risk scoring (Random Forest)
- One-click vendor security scans
- Risk level: Low / Medium / High / Critical

### Threat Intelligence
- ML threat classifier (Naive Bayes + TF-IDF)
- Classifies text as: Benign / Suspicious / Phishing / Malware
- Real domain scanning (SSL, headers, open ports)

### ML Anomaly Detection
- Isolation Forest model detects unusual user behaviour
- Flags odd-hour logins, bulk exports, mass deletions
- Auto-creates alerts for high-confidence anomalies

### Attack Simulation (Demo Mode)
- Brute Force Login
- Data Exfiltration
- Insider Threat
- Credential Stuffing

### Multi-User Monitoring (Admin Only)
- Track all users: IP address, device, last action, page visited
- Live activity feed (auto-refreshes every 10s)
- Per-user activity history with anomaly scores
- Add / promote / delete users from UI

### Reports (5 Types)
- Security Posture Report
- Vendor Risk Assessment
- Executive Summary
- Incident & Threat Report
- Compliance Status Report

---

## 🚀 Quick Start (Local)

```bash
# 1. Clone / extract the project
cd cyberguard_prod

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy env file
cp .env.example backend/.env

# 4. Run
python backend/main.py
```

Open: `http://127.0.0.1:8000`

**Default credentials:**
| Email | Password | Role |
|---|---|---|
| admin@company.com | password | Admin |
| priya@company.com | password123 | IT Analyst |
| rahul@company.com | password123 | DevOps |
| sara@company.com | password123 | Security Engineer |
| james@company.com | password123 | Network Admin |

---

## 🌐 Deploy to Render (Free)

1. Push this project to a **GitHub repo**
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Render auto-detects `render.yaml` and configures everything
5. Set environment variables in Render dashboard:
   - `SECRET_KEY` → generate a random one
   - `DATABASE_URL` → use Render's free PostgreSQL
6. Deploy → get your live URL!

---

## 🏗 Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) |
| Database | SQLite (local) / PostgreSQL (production) |
| Auth | JWT (python-jose) |
| ML | scikit-learn (Isolation Forest, Random Forest, Naive Bayes) |
| Frontend | Vanilla JS + Chart.js |
| Deployment | Render.com |

---

## 📁 Project Structure

```
cyberguard_prod/
├── backend/
│   ├── main.py          # FastAPI app — all routes + ML
│   ├── .env             # Environment variables (not committed)
│   └── ml/
│       └── saved_models/ # Trained ML model pickles
├── frontend/
│   └── index.html       # Single-page app
├── requirements.txt
├── render.yaml          # Render deployment config
├── Procfile
├── .gitignore
└── .env.example
```

---

## 🔒 Security Notes

- JWT tokens expire after 12 hours
- Passwords hashed with Werkzeug (PBKDF2)
- Admin endpoints protected by role check
- CORS configurable via environment variable
- Never commit `.env` to GitHub

---

## 👨‍💻 Built With

- **ML Models:** 3 custom-trained models for anomaly detection, vendor risk scoring, and threat classification
- **Real Scanning:** Live SSL certificate, HTTP security header, and open port checks
- **Multi-User:** Full activity tracking with IP, device, and page visit logging

---

*CyberGuard v2.0 — Major Project | Computer Science*
