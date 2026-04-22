# 🛡 CyberGuard v2.0 — Enterprise Cybersecurity Risk Platform

A production-ready, full-stack cybersecurity risk management platform. CyberGuard provides real-time multi-user monitoring, endpoint telemetry, ML-powered anomaly detection, insider threat modeling, and vendor risk assessment.

**Live Demo:** [Deploy to Render →](#deploy-to-render-free)

---

## ✨ Core Features

### 💻 Endpoint Monitoring & Insider Threat Detection
- **Lightweight python agent** (`agent/monitor.py`) capturing desktop telemetry.
- Track all users: IP address, device, active windows, and pages visited.
- **Insider Threat Detection** implementing LSTM-Autoencoder models (inspired by Nasir et al. IEEE ACCESS 2021) for advanced behavioral profiling.
- Live admin feed of employee activity.

### 🤖 ML-Powered Threat Intelligence
- **Anomaly Detection (Isolation Forest)**: Flags odd-hour logins, mass deletions, and strange behavior from employee telemetry.
- **Threat Classifier (Naive Bayes + TF-IDF)**: Classifies text data as Benign, Suspicious, Phishing, or Malware.
- **Vendor Risk Scoring (Random Forest)**: Automated risk grading for third-party vendors.

### 🏢 Vendor Risk Management
- Track unlimited third-party vendors with automatically assigned risk levels.
- Real domain attack-surface scanning (SSL, headers, open ports).

### 🚨 Alert & Posture Management
- Security Posture dashboard (0-950 score).
- Auto-created alerts for High Confidence ML Anomalies and Threat Detection.
- 5 comprehensive exportable compliance and security reports.

---

## 🚀 Quick Start (Local)

### 1. Start the Backend
```bash
# 1. Clone / extract the project
cd cyberguard_prod

# 2. Install dependencies
pip install -r requirements.txt

# 3. Secure environment variables
cp .env.example backend/.env

# 4. Run the server
python backend/main.py
```
*The web UI will be available at `http://127.0.0.1:8000`*

### 2. Deploy Endpoint Agent (Worker Tracking)
On the employee's machine:
```bash
# Install requirements
pip install requests pygetwindow

# Run agent to send telemetry to the backend
python agent/monitor.py --key <USER_TRACKING_KEY> --server http://127.0.0.1:8000
```


**Default credentials for Demo Phase:**
| Email | Password | Role |
|---|---|---|
| admin@company.com | password123 | Admin |
| priya@company.com | password123 | IT Analyst |
| rahul@company.com | password123 | DevOps |

---

## 🌐 Deploy to Render (Production)

1. Push this project to a **GitHub repo**
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repository.
4. Render auto-detects `render.yaml` and configures everything.
5. Provide strict environment variables in the Render dashboard:
   - `SECRET_KEY` → Highly secure random string.
   - `DATABASE_URL` → Render's free PostgreSQL URL.
   - `ALLOWED_ORIGINS` → Explicitly define allowed remote origins.
6. Deploy → Get your live URL!

---

## 📁 Project Structure

```
cyberguard_prod/
├── agent/               # Endpoint tracking agent for employees
│   └── monitor.py
├── backend/             # FastAPI REST Server
│   ├── config.py        # Environment configs & CORS
│   ├── database.py      # SQLAlchemy Models
│   ├── auth.py          # JWT logic
│   ├── ml/              # Scikit-Learn models (IsolationForest, RF, NB)
│   │   ├── anomaly.py
│   │   ├── threat.py
│   │   └── vendor.py
│   └── routes/          # Modularized endpoints (monitoring.py, logs.py, etc)
├── frontend/            # Vanilla JS + CSS Client
│   ├── index.html       
│   ├── css/styles.css   # Responsive UI
│   └── js/              # Client logic
├── requirements.txt     # Python Dependencies
├── render.yaml          # Render deployment config
└── .env.example         # Template for environment
```

---

## 🔒 Security Posture

- **Secure Secrets:** Random ephemeral key generation if `SECRET_KEY` is missing in production. 
- **Type-safe Endpoints:** Full Pydantic validation across endpoints. 
- **Sanitized Inputs:** Defensive sanitization against simple payload injection algorithms on UI telemetry capture. 
- **Robust Persistence:** `joblib` memory dumps instead of insecure `.pkl` files.
- **Admin Guards:** System-critical endpoints (ML retraining, Activity Deletion, Simulation) locked behind strict Admin authorization headers.

---

*CyberGuard v2.0 — Major Project | Computer Science*
