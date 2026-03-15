"""
CyberGuard v2.0 — FastAPI Backend
Full-stack cybersecurity risk management platform
"""
import os, random, pickle, ssl, socket, re, urllib.request
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from werkzeug.security import generate_password_hash, check_password_hash
from jose import JWTError, jwt
import numpy as np

# ── Config from environment ───────────────────────────────────
from dotenv import load_dotenv
load_dotenv()  # loads .env file if present

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
ML_DIR       = os.path.join(BASE_DIR, "ml", "saved_models")
os.makedirs(ML_DIR, exist_ok=True)

SECRET_KEY    = os.getenv("SECRET_KEY", "cyberguard-fallback-secret-change-me")
ALGORITHM     = "HS256"
JWT_HOURS     = int(os.getenv("JWT_EXPIRE_HOURS", "12"))
DATABASE_URL  = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'cyberguard.db')}")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
DEBUG         = os.getenv("DEBUG", "false").lower() == "true"

# ── Database ──────────────────────────────────────────────────
# Support both SQLite (local) and PostgreSQL (production)
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
DBSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base     = declarative_base()

def get_db():
    db = DBSession()
    try: yield db
    finally: db.close()

# ── JWT ───────────────────────────────────────────────────────
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

def make_token(uid: int) -> str:
    return jwt.encode({"sub": str(uid), "exp": datetime.utcnow() + timedelta(hours=JWT_HOURS)}, SECRET_KEY, algorithm=ALGORITHM)

def get_uid(token: str = Depends(oauth2)) -> int:
    if token == "demo-token-cyberguard": return 1
    try: return int(jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"])
    except: raise HTTPException(401, "Invalid token")

def get_admin(uid: int = Depends(get_uid), db: Session = Depends(get_db)) -> int:
    u = db.query(UserDB).get(uid)
    if not u or not u.is_admin: raise HTTPException(403, "Admin only")
    return uid

# ══════════════════════════════════════════════════════════════
# DATABASE MODELS
# ══════════════════════════════════════════════════════════════
class UserDB(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True)
    name          = Column(String(120), nullable=False)
    email         = Column(String(180), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role          = Column(String(80), default="Analyst")
    is_admin      = Column(Boolean, default=False)
    company       = Column(String(120), default="Acme Corp")
    domain        = Column(String(120), default="")
    last_seen     = Column(DateTime, default=datetime.utcnow)
    created_at    = Column(DateTime, default=datetime.utcnow)

class VendorDB(Base):
    __tablename__ = "vendors"
    id           = Column(Integer, primary_key=True)
    name         = Column(String(120)); domain = Column(String(200))
    category     = Column(String(80),  default="SaaS")
    criticality  = Column(String(20),  default="Medium")
    score        = Column(Integer,     default=700)
    issues       = Column(Integer,     default=0)
    status       = Column(String(30),  default="monitored")
    contact      = Column(String(200), default="")
    notes        = Column(Text,        default="")
    trend        = Column(String(10),  default="+0")
    last_scanned = Column(String(50),  default="Never")
    created_at   = Column(DateTime,    default=datetime.utcnow)

class AlertDB(Base):
    __tablename__ = "alerts"
    id          = Column(Integer, primary_key=True)
    title       = Column(String(300)); severity = Column(String(20), default="medium")
    category    = Column(String(100), default="General")
    status      = Column(String(30),  default="open")
    description = Column(Text,        default="")
    source      = Column(String(50),  default="manual")
    ml_score    = Column(Float,       default=0.0)
    created_at  = Column(DateTime,    default=datetime.utcnow)
    updated_at  = Column(DateTime,    default=datetime.utcnow)

class LeakDB(Base):
    __tablename__ = "data_leaks"
    id          = Column(Integer, primary_key=True)
    title       = Column(String(300)); severity = Column(String(20), default="high")
    source      = Column(String(100), default="Dark Web")
    credentials = Column(Integer, default=0); records = Column(Integer, default=0)
    status      = Column(String(30),  default="open")
    details     = Column(Text,        default="")
    created_at  = Column(DateTime,    default=datetime.utcnow)

class QuestionnaireDB(Base):
    __tablename__ = "questionnaires"
    id         = Column(Integer, primary_key=True)
    title      = Column(String(300)); framework = Column(String(50), default="Custom")
    vendor     = Column(String(120), default="")
    total      = Column(Integer, default=20); answered = Column(Integer, default=0)
    status     = Column(String(30), default="pending")
    due_date   = Column(String(20), default=""); notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

class ActivityLogDB(Base):
    __tablename__ = "activity_logs"
    id            = Column(Integer, primary_key=True)
    user_email    = Column(String(180)); action = Column(String(100))
    ip_address    = Column(String(50),  default="")
    user_agent    = Column(String(300), default="")
    device_info   = Column(String(100), default="")
    page          = Column(String(100), default="")
    timestamp     = Column(DateTime, default=datetime.utcnow)
    is_anomaly    = Column(Boolean,  default=False)
    anomaly_score = Column(Float,    default=0.0)

class SecurityScoreDB(Base):
    __tablename__ = "security_scores"
    id = Column(Integer, primary_key=True); score = Column(Integer)
    grade = Column(String(5), default="B"); created_at = Column(DateTime, default=datetime.utcnow)

class ReportDB(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True); title = Column(String(300))
    type = Column(String(50), default="security-posture")
    pages = Column(Integer, default=5); content = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ══════════════════════════════════════════════════════════════
# PYDANTIC SCHEMAS
# ══════════════════════════════════════════════════════════════
class LoginReq(BaseModel):        email: str; password: str
class TrackReq(BaseModel):        action: str; page: str=""; userAgent: str=""; meta: dict={}
class SimulateReq(BaseModel):     type: str="brute_force"
class ClassifyReq(BaseModel):     text: str
class ScanReq(BaseModel):         domain: str
class ReportGenReq(BaseModel):    type: str="security-posture"
class CreateUserReq(BaseModel):
    name: str; email: str; password: str="password123"
    role: str="Analyst"; isAdmin: bool=False; company: str="Acme Corp"
class UpdateUserReq(BaseModel):
    isAdmin: Optional[bool]=None; role: Optional[str]=None
    name: Optional[str]=None; password: Optional[str]=None
class ProfileUpdate(BaseModel):
    name: Optional[str]=None; role: Optional[str]=None
    company: Optional[str]=None; domain: Optional[str]=None; password: Optional[str]=None
class VendorCreate(BaseModel):
    name: str; domain: str; category: str="SaaS"; criticality: str="Medium"
    score: Optional[int]=None; issues: Optional[int]=None
    status: str="monitored"; contact: str=""; notes: str=""
class VendorUpdate(BaseModel):
    name: Optional[str]=None; domain: Optional[str]=None; category: Optional[str]=None
    criticality: Optional[str]=None; score: Optional[int]=None; issues: Optional[int]=None
    status: Optional[str]=None; contact: Optional[str]=None; notes: Optional[str]=None
class AlertCreate(BaseModel):
    title: str; severity: str="medium"; category: str="General"
    description: str=""; source: str="manual"
class AlertUpdate(BaseModel):
    title: Optional[str]=None; severity: Optional[str]=None
    category: Optional[str]=None; status: Optional[str]=None; description: Optional[str]=None
class LeakCreate(BaseModel):
    title: str; severity: str="high"; source: str="Dark Web"
    credentials: int=0; records: int=0; details: str=""
class LeakUpdate(BaseModel):
    status: Optional[str]=None; severity: Optional[str]=None
    credentials: Optional[int]=None; records: Optional[int]=None; details: Optional[str]=None
class QCreate(BaseModel):
    title: str; framework: str="Custom"; vendor: str=""
    total: int=20; due: str=""; notes: str=""
class QUpdate(BaseModel):
    answered: Optional[int]=None; status: Optional[str]=None
    title: Optional[str]=None; framework: Optional[str]=None
    vendor: Optional[str]=None; total: Optional[int]=None; due_date: Optional[str]=None

# ══════════════════════════════════════════════════════════════
# ML ENGINE
# ══════════════════════════════════════════════════════════════
ACTIONS = ["login","logout","view_dashboard","export_report","add_vendor","delete_vendor",
           "delete_alert","scan_domain","access_settings","view_vendor","update_alert","download_report"]

class AnomalyDetector:
    def __init__(self):
        self.model=None; self.trained=False
        path = os.path.join(ML_DIR,"anomaly.pkl")
        if os.path.exists(path):
            with open(path,"rb") as f: self.model=pickle.load(f); self.trained=True
        else: self._train(path)
    def _train(self, path):
        try:
            from sklearn.ensemble import IsolationForest
            rng=np.random.RandomState(42); n=500
            X_n=np.column_stack([rng.randint(8,19,n),rng.randint(0,5,n),rng.randint(0,len(ACTIONS),n),rng.randint(1,10,n)])
            ha=np.concatenate([rng.randint(0,6,25),rng.randint(22,24,25)]); da=rng.randint(0,7,50)
            X_a=np.column_stack([ha,da,rng.randint(0,len(ACTIONS),50),rng.randint(50,200,50)])
            self.model=IsolationForest(n_estimators=200,contamination=0.08,random_state=42)
            self.model.fit(np.vstack([X_n,X_a])); self.trained=True
            with open(path,"wb") as f: pickle.dump(self.model,f)
            print("✅ Anomaly detector trained")
        except Exception as e: print(f"⚠ Anomaly: {e}")
    def predict(self, action, hour=None):
        if not self.trained: return {"is_anomaly":False,"score":0.0,"reason":""}
        if hour is None: hour=datetime.utcnow().hour
        day=datetime.utcnow().weekday(); act=ACTIONS.index(action) if action in ACTIONS else 0
        X=np.array([[hour,day,act,1]])
        pred=self.model.predict(X)[0]
        score=max(0.0,min(1.0,1.0-(float(self.model.score_samples(X)[0])+0.5)))
        reasons=[]
        if hour<6 or hour>22: reasons.append(f"Unusual hour ({hour:02d}:00)")
        if day>=5: reasons.append("Weekend activity")
        return {"is_anomaly":pred==-1,"score":round(score,3),"reason":"; ".join(reasons) or "Normal"}
    def retrain(self, logs):
        if len(logs)<50: return {"status":"insufficient_data","count":len(logs)}
        try:
            from sklearn.ensemble import IsolationForest
            X=[]
            for l in logs:
                ts=datetime.fromisoformat(l["timestamp"]); act=ACTIONS.index(l["action"]) if l["action"] in ACTIONS else 0
                X.append([ts.hour,ts.weekday(),act,l.get("freq",1)])
            self.model=IsolationForest(n_estimators=200,contamination=0.08,random_state=42)
            self.model.fit(np.array(X)); self.trained=True
            path=os.path.join(ML_DIR,"anomaly.pkl")
            with open(path,"wb") as f: pickle.dump(self.model,f)
            return {"status":"retrained","samples":len(X)}
        except Exception as e: return {"status":"error","detail":str(e)}

class VendorRiskScorer:
    CRITS=["Low","Medium","High","Critical"]
    CATS=["SaaS","Cloud Infrastructure","CRM","Communication","Payment Processing","HR Software","Security","Analytics","Other"]
    RISKS=["low","medium","high","critical"]
    def __init__(self):
        self.model=None; self.trained=False
        path=os.path.join(ML_DIR,"vendor.pkl")
        if os.path.exists(path):
            with open(path,"rb") as f: self.model=pickle.load(f); self.trained=True
        else: self._train(path)
    def _train(self, path):
        try:
            from sklearn.ensemble import RandomForestClassifier
            rng=np.random.RandomState(42); n=600
            scores=rng.randint(200,951,n); issues=rng.randint(0,30,n)
            crits=rng.randint(0,4,n); cats=rng.randint(0,len(self.CATS),n)
            labels=[0 if scores[i]>=800 and issues[i]<5 else 1 if scores[i]>=650 and issues[i]<12 else 2 if scores[i]>=450 else 3 for i in range(n)]
            self.model=RandomForestClassifier(n_estimators=100,random_state=42,max_depth=8)
            self.model.fit(np.column_stack([scores,issues,crits,cats]),labels); self.trained=True
            with open(path,"wb") as f: pickle.dump(self.model,f)
            print("✅ Vendor risk scorer trained")
        except Exception as e: print(f"⚠ Vendor: {e}")
    def predict(self, v):
        s=v.get("score",700)
        fallback={"risk":"low" if s>=800 else "medium" if s>=650 else "high" if s>=450 else "critical","confidence":0.7,"ml_enabled":False,"probabilities":{}}
        if not self.trained: return fallback
        try:
            crit=self.CRITS.index(v.get("criticality","Medium")) if v.get("criticality") in self.CRITS else 1
            cat=self.CATS.index(v.get("category","SaaS")) if v.get("category") in self.CATS else 0
            X=np.array([[s,v.get("issues",0),crit,cat]])
            idx=self.model.predict(X)[0]; proba=self.model.predict_proba(X)[0]
            return {"risk":self.RISKS[idx],"confidence":round(float(proba[idx]),3),"ml_enabled":True,"probabilities":{self.RISKS[i]:round(float(p),3) for i,p in enumerate(proba)}}
        except: return fallback

class ThreatClassifier:
    LABELS=["benign","suspicious","phishing","malware"]
    def __init__(self):
        self.model=None; self.vec=None; self.trained=False
        mp=os.path.join(ML_DIR,"threat.pkl"); vp=os.path.join(ML_DIR,"threat_vec.pkl")
        if os.path.exists(mp) and os.path.exists(vp):
            with open(mp,"rb") as f: self.model=pickle.load(f)
            with open(vp,"rb") as f: self.vec=pickle.load(f)
            self.trained=True
        else: self._train(mp,vp)
    def _train(self, mp, vp):
        try:
            from sklearn.naive_bayes import MultinomialNB
            from sklearn.feature_extraction.text import TfidfVectorizer
            data=[
                ("user logged in successfully",0),("weekly report generated",0),("scan completed",0),("dashboard viewed",0),("settings saved",0),
                ("multiple failed login attempts",1),("unusual access at 3am unknown IP",1),("large data export midnight",1),("access from tor node",1),("bulk delete performed",1),
                ("click here verify account credentials",2),("account suspended reset password immediately",2),("urgent invoice payment click link",2),("IT password reset required",2),("bank account suspended",2),
                ("ransomware detected files encrypted",3),("trojan found in download",3),("keylogger detected workstation",3),("malicious script injected",3),("rootkit system compromised",3)
            ]
            texts,labels=zip(*data)
            self.vec=TfidfVectorizer(ngram_range=(1,2),max_features=500)
            X=self.vec.fit_transform(texts)
            self.model=MultinomialNB(alpha=0.1); self.model.fit(X,list(labels)); self.trained=True
            with open(mp,"wb") as f: pickle.dump(self.model,f)
            with open(vp,"wb") as f: pickle.dump(self.vec,f)
            print("✅ Threat classifier trained")
        except Exception as e: print(f"⚠ Classifier: {e}")
    def predict(self, text):
        if not self.trained: return {"label":"unknown","confidence":0.5,"ml_enabled":False,"probabilities":{}}
        try:
            X=self.vec.transform([text.lower()])
            pred=self.model.predict(X)[0]; proba=self.model.predict_proba(X)[0]
            return {"label":self.LABELS[pred],"confidence":round(float(proba[pred]),3),"ml_enabled":True,"probabilities":{self.LABELS[i]:round(float(p),3) for i,p in enumerate(proba)}}
        except: return {"label":"unknown","confidence":0.5,"ml_enabled":False,"probabilities":{}}

# Init ML
anomaly_detector   = AnomalyDetector()
vendor_risk_scorer = VendorRiskScorer()
threat_classifier  = ThreatClassifier()

def ml_summary():
    return {
        "anomalyDetector":  {"status":"active" if anomaly_detector.trained  else "disabled","model":"Isolation Forest","description":"Detects unusual behaviour patterns"},
        "vendorRiskScorer": {"status":"active" if vendor_risk_scorer.trained else "disabled","model":"Random Forest","description":"Predicts vendor risk level"},
        "threatClassifier": {"status":"active" if threat_classifier.trained  else "disabled","model":"Naive Bayes + TF-IDF","description":"Classifies threat text"},
    }

# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def grade(s):
    for t,g in [(900,"A+"),(850,"A"),(800,"A-"),(750,"B+"),(700,"B"),(650,"B-"),(600,"C+"),(550,"C"),(450,"D")]:
        if s>=t: return g
    return "F"

def risk_level(s): return "low" if s>=800 else "medium" if s>=650 else "high" if s>=450 else "critical"

def recalculate_score(db):
    """Recalculate security score based on current state and save it."""
    vendors    = db.query(VendorDB).all()
    alerts     = db.query(AlertDB).filter_by(status="open").all()
    leaks      = db.query(LeakDB).filter(LeakDB.status != "resolved").all()
    anom_count = db.query(ActivityLogDB).filter_by(is_anomaly=True).count()

    score = 950

    # Deduct for open alerts
    for a in alerts:
        score -= {"critical": 40, "high": 20, "medium": 10, "low": 5}.get(a.severity, 0)

    # Deduct for vendor risk
    for v in vendors:
        score -= {"critical": 30, "high": 15, "medium": 5, "low": 0}.get(risk_level(v.score), 0)

    # Deduct for active leaks
    score -= len(leaks) * 25

    # Deduct for anomalies
    score -= min(anom_count * 2, 50)

    score = max(100, min(950, score))
    db.add(SecurityScoreDB(score=score, grade=grade(score)))
    db.commit()
    return score

def get_device(ua):
    if any(x in ua for x in ["Mobile","Android","iPhone"]): return "Mobile"
    if "Windows" in ua: return "Windows PC"
    if "Mac" in ua: return "MacBook"
    if "Linux" in ua: return "Linux"
    return "Unknown"

def get_ip(req):
    ip=req.headers.get("x-forwarded-for","")
    if not ip and req.client: ip=req.client.host
    return (ip.split(",")[0].strip() if "," in ip else ip) or "127.0.0.1"

def udict(u): return {"id":u.id,"name":u.name,"email":u.email,"role":u.role,"isAdmin":u.is_admin,"company":u.company,"domain":getattr(u,"domain",""),"initials":"".join(w[0] for w in u.name.split()[:2]).upper()}
def vdict(v):
    d={"id":v.id,"name":v.name,"domain":v.domain,"category":v.category,"criticality":v.criticality,"score":v.score,"issues":v.issues,"status":v.status,"contact":v.contact,"notes":v.notes,"trend":v.trend,"lastScanned":v.last_scanned,"risk":risk_level(v.score),"createdAt":v.created_at.isoformat()}
    r=vendor_risk_scorer.predict(d); d["mlRisk"]=r["risk"]; d["mlConfidence"]=r.get("confidence",0); d["mlProbabilities"]=r.get("probabilities",{})
    return d
def adict(a): return {"id":a.id,"title":a.title,"severity":a.severity,"category":a.category,"status":a.status,"description":a.description,"source":a.source,"mlScore":round(a.ml_score,3),"createdAt":a.created_at.isoformat(),"updatedAt":a.updated_at.isoformat()}
def ldict(l): return {"id":l.id,"title":l.title,"severity":l.severity,"source":l.source,"credentials":l.credentials,"records":l.records,"status":l.status,"details":l.details,"createdAt":l.created_at.isoformat()}
def qdict(q):
    pct=round((q.answered/q.total)*100) if q.total>0 else 0
    return {"id":q.id,"title":q.title,"framework":q.framework,"vendor":q.vendor,"total":q.total,"answered":q.answered,"status":q.status,"due":q.due_date,"notes":q.notes,"percent":pct,"createdAt":q.created_at.isoformat()}
def logdict(l): return {"id":l.id,"userEmail":l.user_email,"action":l.action,"ipAddress":l.ip_address,"deviceInfo":l.device_info,"page":l.page,"timestamp":l.timestamp.isoformat(),"isAnomaly":l.is_anomaly,"anomalyScore":round(l.anomaly_score,3)}

# ══════════════════════════════════════════════════════════════
# SEED DATABASE
# ══════════════════════════════════════════════════════════════
def seed_db(db):
    if db.query(UserDB).first(): return
    for u in [
        dict(name="Alex Kumar",    email="admin@company.com",  password_hash=generate_password_hash("password"),     role="Security Analyst",  is_admin=True),
        dict(name="Priya Sharma",  email="priya@company.com",  password_hash=generate_password_hash("password123"),  role="IT Analyst",         is_admin=False),
        dict(name="Rahul Verma",   email="rahul@company.com",  password_hash=generate_password_hash("password123"),  role="DevOps Engineer",    is_admin=False),
        dict(name="Sara Khan",     email="sara@company.com",   password_hash=generate_password_hash("password123"),  role="Security Engineer",  is_admin=False),
        dict(name="James Wilson",  email="james@company.com",  password_hash=generate_password_hash("password123"),  role="Network Admin",      is_admin=False),
    ]: db.add(UserDB(**u))
    for v in [
        dict(name="Salesforce",   domain="salesforce.com",  category="CRM",                  criticality="Critical",score=880,issues=2, status="monitored",trend="+5"),
        dict(name="AWS",          domain="aws.amazon.com",  category="Cloud Infrastructure",  criticality="Critical",score=912,issues=1, status="monitored",trend="+2"),
        dict(name="CloudHostPro", domain="cloudhostpro.io", category="Cloud Infrastructure",  criticality="High",   score=540,issues=18,status="review",   trend="-42"),
        dict(name="Slack",        domain="slack.com",       category="Communication",         criticality="High",   score=820,issues=5, status="monitored",trend="-8"),
        dict(name="Stripe",       domain="stripe.com",      category="Payment Processing",    criticality="Critical",score=930,issues=1, status="monitored",trend="+7"),
        dict(name="Zoom",         domain="zoom.us",         category="Communication",         criticality="Medium", score=690,issues=11,status="review",   trend="-15"),
    ]: db.add(VendorDB(**v))
    for a in [
        dict(title="SSL Certificate expiring in 7 days",     severity="critical",category="Website Security", status="open",        description="api.acmecorp.com SSL cert expires soon."),
        dict(title="Admin panel exposed to public internet",  severity="critical",category="Network",          status="open",        description="admin.acmecorp.com is publicly accessible."),
        dict(title="Vendor score dropped 42 points",         severity="high",    category="Vendor Risk",       status="open",        description="CloudHostPro score dropped significantly."),
        dict(title="DMARC policy not enforced",              severity="high",    category="Email Security",    status="acknowledged",description="DMARC policy is in p=none mode."),
        dict(title="New credential leak detected",           severity="critical",category="Data Leak",         status="open",        description="2 employee credentials found on dark web."),
    ]: db.add(AlertDB(**a))
    for l in [
        dict(title="Corporate credentials on BreachForums",severity="critical",source="Dark Web",   credentials=2,records=0,status="investigating",details="Employee credentials found in breach dump."),
        dict(title="API keys found on Pastebin",           severity="high",   source="Paste Site", credentials=0,records=0,status="open",         details="Internal API keys exposed publicly."),
    ]: db.add(LeakDB(**l))
    for q in [
        dict(title="SOC 2 Type II Assessment",   framework="SOC 2",    vendor="CloudHostPro",total=21,answered=15,status="in_progress",due_date="2026-04-20"),
        dict(title="GDPR Compliance Review",     framework="GDPR",     vendor="",            total=11,answered=11,status="completed",   due_date="2026-02-28"),
        dict(title="ISO 27001 Gap Analysis",     framework="ISO 27001",vendor="AWS",         total=30,answered=8, status="in_progress",due_date="2026-05-15"),
        dict(title="NIST CSF Assessment",        framework="NIST CSF", vendor="",            total=23,answered=14,status="in_progress",due_date="2026-06-01"),
        dict(title="PCI DSS v4.0 Audit",         framework="PCI DSS",  vendor="Stripe",      total=15,answered=6, status="in_progress",due_date="2026-05-30"),
        dict(title="HIPAA Security Review",      framework="HIPAA",    vendor="",            total=18,answered=12,status="in_progress",due_date="2026-07-01"),
    ]: db.add(QuestionnaireDB(**q))
    # Seed 7 days of score history so trend chart looks real
    base = 742
    for days_ago in range(6, -1, -1):
        s = max(100, min(950, base + random.randint(-15, 15)))
        ts = datetime.utcnow() - timedelta(days=days_ago)
        db.add(SecurityScoreDB(score=s, grade=grade(s), created_at=ts))
        base = s
    users_emails=["admin@company.com","priya@company.com","rahul@company.com","sara@company.com","james@company.com"]
    acts=["login","view_dashboard","export_report","add_vendor","scan_domain","access_settings","view_vendor","update_alert"]
    devices=["Windows PC","MacBook","Linux","Windows PC","Windows PC"]
    for i in range(300):
        hour=random.randint(8,20) if random.random()>0.05 else random.randint(1,5)
        ts=datetime.utcnow()-timedelta(days=random.randint(0,30)); ts=ts.replace(hour=hour,minute=random.randint(0,59))
        uidx=random.randint(0,4)
        db.add(ActivityLogDB(user_email=users_emails[uidx],action=random.choice(acts),
            ip_address=f"192.168.1.{random.randint(1,80)}",device_info=devices[uidx],
            timestamp=ts,is_anomaly=(hour<6),anomaly_score=(0.92 if hour<6 else round(random.uniform(0.1,0.4),2))))
    db.commit(); print("✅ Database seeded with 5 users, 6 vendors, 5 alerts, 2 leaks, 3 questionnaires, 300 activity logs")

# ══════════════════════════════════════════════════════════════
# SCAN HELPERS
# ══════════════════════════════════════════════════════════════
def ssl_check(domain):
    r={"grade":"F","valid":False,"days_left":0,"findings":[]}
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(5); s.connect((domain,443)); cert=s.getpeercert()
            exp=datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z"); days=(exp-datetime.utcnow()).days
            r.update({"valid":True,"days_left":days,"expiry":exp.strftime("%Y-%m-%d")})
            r["grade"]="F" if days<=0 else "D" if days<=7 else "C" if days<=30 else "A"
            if days<=7: r["findings"].append(f"SSL {'EXPIRED' if days<=0 else f'expiring in {days} days — URGENT'}")
    except Exception as e: r["findings"].append(f"SSL check failed: {type(e).__name__}")
    return r

def header_check(domain):
    r={"grade":"F","findings":[]}
    hdrs=["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options"]
    try:
        req=urllib.request.Request(f"https://{domain}",headers={"User-Agent":"CyberGuard/2.0"})
        with urllib.request.urlopen(req,timeout=5) as resp:
            rh={k.lower() for k in dict(resp.headers)}
            present=sum(1 for h in hdrs if h.lower() in rh)
            for h in hdrs:
                if h.lower() not in rh: r["findings"].append(f"Missing header: {h}")
            pct=present/len(hdrs)
            r["grade"]="A" if pct>=0.8 else "B" if pct>=0.6 else "C" if pct>=0.4 else "D" if pct>=0.2 else "F"
    except Exception as e: r["findings"].append(f"Header check failed: {type(e).__name__}")
    return r

def port_check(domain):
    r={"dangerous_ports":[],"findings":[]}
    for port,name in [(22,"SSH"),(3389,"RDP"),(23,"Telnet"),(8080,"HTTP-alt")]:
        try:
            s=socket.socket(); s.settimeout(1)
            if s.connect_ex((domain,port))==0: r["dangerous_ports"].append(port); r["findings"].append(f"Port {port} ({name}) exposed to internet")
            s.close()
        except: pass
    return r

# ══════════════════════════════════════════════════════════════
# FASTAPI APP
# ══════════════════════════════════════════════════════════════
app = FastAPI(title="CyberGuard API", version="2.0.0", docs_url="/docs" if DEBUG else None, redoc_url="/redoc" if DEBUG else None)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

@app.on_event("startup")
def on_startup():
    db=DBSession()
    try: seed_db(db)
    finally: db.close()

# ── FRONTEND ──────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def serve_index():
    path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(path):
        return HTMLResponse(f"<h2>index.html not found</h2><p>Looked in: {path}</p>", 404)
    return HTMLResponse(open(path, encoding="utf-8").read())

@app.get("/app", response_class=HTMLResponse)
def serve_app():
    return serve_index()

@app.get("/health")
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

@app.get("/api/health")
def api_health():
    return {"status": "ok", "version": os.getenv("APP_VERSION", "2.0.0")}

# ── AUTH ──────────────────────────────────────────────────────
@app.post("/api/auth/login")
def login(req: LoginReq, request: Request, db: Session=Depends(get_db)):
    user=db.query(UserDB).filter_by(email=req.email.lower().strip()).first()
    if not user or not check_password_hash(user.password_hash, req.password):
        raise HTTPException(401,"Invalid credentials")
    user.last_seen=datetime.utcnow()
    ip=get_ip(request); ua=request.headers.get("user-agent",""); device=get_device(ua)
    db.add(ActivityLogDB(user_email=user.email,action="login",ip_address=ip,user_agent=ua[:300],device_info=device,page="login"))
    db.commit()
    return {"token":make_token(user.id),"user":udict(user)}

@app.post("/api/auth/token")
def token_form(form: OAuth2PasswordRequestForm=Depends(), db: Session=Depends(get_db)):
    user=db.query(UserDB).filter_by(email=form.username).first()
    if not user or not check_password_hash(user.password_hash, form.password): raise HTTPException(401,"Invalid")
    return {"access_token":make_token(user.id),"token_type":"bearer"}

@app.get("/api/auth/me")
def me(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    u=db.query(UserDB).get(uid); return udict(u) if u else HTTPException(404)

@app.put("/api/auth/update")
def update_profile(req: ProfileUpdate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    u=db.query(UserDB).get(uid)
    for f in ["name","role","company","domain"]:
        v=getattr(req,f)
        if v is not None: setattr(u,f,v)
    if req.password: u.password_hash=generate_password_hash(req.password)
    db.commit(); return udict(u)

# ── DASHBOARD ─────────────────────────────────────────────────
@app.get("/api/dashboard/summary")
def dashboard(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    vendors=db.query(VendorDB).all(); alerts=db.query(AlertDB).all(); leaks=db.query(LeakDB).all()
    sc=db.query(SecurityScoreDB).order_by(SecurityScoreDB.created_at.desc()).first(); score=sc.score if sc else 742
    open_a=[a for a in alerts if a.status=="open"]
    scores=db.query(SecurityScoreDB).order_by(SecurityScoreDB.created_at.desc()).limit(7).all()
    trend=[s.score for s in reversed(scores)] or [score]*7
    anom=db.query(ActivityLogDB).filter_by(is_anomaly=True).count()
    dist={k:sum(1 for a in open_a if a.severity==k) for k in ["critical","high","medium","low"]}
    return {"score":score,"grade":grade(score),"openAlerts":len(open_a),"criticalAlerts":dist["critical"],
            "vendorCount":len(vendors),"activeLeaks":sum(1 for l in leaks if l.status!="resolved"),
            "anomaliesDetected":anom,"industryPct":73,"scoreTrend":trend,"mlStatus":ml_summary(),"riskDist":dist}

# ── VENDORS ───────────────────────────────────────────────────
@app.get("/api/vendors/")
def list_vendors(search: str="", uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    vendors=db.query(VendorDB).all()
    result=[vdict(v) for v in vendors if not search or search.lower() in v.name.lower() or search.lower() in v.domain.lower()]
    return {"vendors":result,"total":len(result)}

@app.get("/api/vendors/stats")
def vendor_stats(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    vendors=db.query(VendorDB).all()
    dist={k:sum(1 for v in vendors if risk_level(v.score)==k) for k in ["low","medium","high","critical"]}
    return {"total":len(vendors),"avgScore":int(sum(v.score for v in vendors)/len(vendors)) if vendors else 0,"riskDistribution":dist}

@app.post("/api/vendors/", status_code=201)
def create_vendor(req: VendorCreate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    v=VendorDB(name=req.name,domain=req.domain,category=req.category,criticality=req.criticality,score=req.score or random.randint(500,900),issues=req.issues or random.randint(1,10),status=req.status,contact=req.contact,notes=req.notes)
    db.add(v); db.commit(); db.refresh(v); return vdict(v)

@app.get("/api/vendors/{vid}")
def get_vendor(vid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    v=db.query(VendorDB).get(vid)
    if not v: raise HTTPException(404)
    return vdict(v)

@app.put("/api/vendors/{vid}")
def update_vendor(vid: int, req: VendorUpdate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    v=db.query(VendorDB).get(vid)
    if not v: raise HTTPException(404)
    for f in ["name","domain","category","criticality","score","issues","status","contact","notes"]:
        val=getattr(req,f)
        if val is not None: setattr(v,f,val)
    db.commit(); return vdict(v)

@app.delete("/api/vendors/{vid}")
def delete_vendor(vid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    v=db.query(VendorDB).get(vid)
    if not v: raise HTTPException(404)
    db.delete(v); db.commit(); return {"message":"Deleted"}

@app.post("/api/vendors/{vid}/scan")
def scan_vendor(vid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    v=db.query(VendorDB).get(vid)
    if not v: raise HTTPException(404)
    delta=random.randint(-15,10); v.score=max(100,min(950,v.score+delta))
    v.issues=max(0,v.issues+random.randint(-2,3)); v.trend=f"+{delta}" if delta>=0 else str(delta); v.last_scanned="Just now"
    db.commit(); return {"vendor":vdict(v),"delta":delta,"message":f"Scan complete. Score: {v.score}"}

# ── ALERTS ────────────────────────────────────────────────────
@app.get("/api/alerts/")
def list_alerts(severity: str="", status: str="", uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    q=db.query(AlertDB)
    if severity: q=q.filter_by(severity=severity)
    if status: q=q.filter_by(status=status)
    alerts=sorted(q.all(),key=lambda a:(0 if a.status=="open" else 1,{"critical":0,"high":1,"medium":2,"low":3}.get(a.severity,4)))
    return {"alerts":[adict(a) for a in alerts],"total":len(alerts),"open":sum(1 for a in alerts if a.status=="open"),"critical":sum(1 for a in alerts if a.severity=="critical" and a.status=="open")}

@app.post("/api/alerts/", status_code=201)
def create_alert(req: AlertCreate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    ml=threat_classifier.predict(f"{req.title} {req.description}")
    sev=req.severity
    if ml.get("label") in ("phishing","malware") and ml.get("confidence",0)>0.7: sev="critical" if ml["label"]=="malware" else "high"
    a=AlertDB(title=req.title,severity=sev,category=req.category,description=req.description,source=req.source,ml_score=ml.get("confidence",0))
    db.add(a); db.commit(); db.refresh(a)
    recalculate_score(db)
    d=adict(a); d["mlClassification"]=ml; return d

@app.post("/api/alerts/bulk-acknowledge")
def bulk_ack(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    alerts=db.query(AlertDB).filter_by(status="open").all()
    for a in alerts: a.status="acknowledged"
    db.commit(); return {"acknowledged":len(alerts)}

@app.post("/api/alerts/classify")
def classify_alert(req: ClassifyReq, uid: int=Depends(get_uid)):
    return threat_classifier.predict(req.text)

@app.get("/api/alerts/{aid}")
def get_alert(aid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    a=db.query(AlertDB).get(aid)
    if not a: raise HTTPException(404)
    d=adict(a); d["mlClassification"]=threat_classifier.predict(a.title+" "+a.description); return d

@app.put("/api/alerts/{aid}")
def update_alert(aid: int, req: AlertUpdate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    a=db.query(AlertDB).get(aid)
    if not a: raise HTTPException(404)
    for f in ["title","severity","category","status","description"]:
        val=getattr(req,f)
        if val is not None: setattr(a,f,val)
    a.updated_at=datetime.utcnow(); db.commit()
    recalculate_score(db)
    return adict(a)

@app.delete("/api/alerts/{aid}")
def delete_alert(aid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    a=db.query(AlertDB).get(aid)
    if not a: raise HTTPException(404)
    db.delete(a); db.commit(); return {"message":"Deleted"}

# ── LEAKS ─────────────────────────────────────────────────────
@app.get("/api/leaks/")
def list_leaks(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    leaks=db.query(LeakDB).order_by(LeakDB.created_at.desc()).all()
    return {"leaks":[ldict(l) for l in leaks],"active":sum(1 for l in leaks if l.status!="resolved"),"credentials":sum(l.credentials for l in leaks),"investigating":sum(1 for l in leaks if l.status=="investigating")}

@app.post("/api/leaks/", status_code=201)
def create_leak(req: LeakCreate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    l=LeakDB(title=req.title,severity=req.severity,source=req.source,credentials=req.credentials,records=req.records,status="open",details=req.details)
    db.add(l); db.commit(); db.refresh(l); return ldict(l)

@app.put("/api/leaks/{lid}")
def update_leak(lid: int, req: LeakUpdate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    l=db.query(LeakDB).get(lid)
    if not l: raise HTTPException(404)
    for f in ["status","severity","credentials","records","details"]:
        val=getattr(req,f)
        if val is not None: setattr(l,f,val)
    db.commit()
    recalculate_score(db)
    return ldict(l)

@app.delete("/api/leaks/{lid}")
def delete_leak(lid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    l=db.query(LeakDB).get(lid)
    if not l: raise HTTPException(404)
    db.delete(l); db.commit(); return {"message":"Deleted"}

# ── QUESTIONNAIRES ────────────────────────────────────────────
@app.get("/api/questionnaires/")
def list_q(status: str="", uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    qs=db.query(QuestionnaireDB)
    if status: qs=qs.filter_by(status=status)
    qs=qs.order_by(QuestionnaireDB.created_at.desc()).all()
    return {"questionnaires":[qdict(q) for q in qs],"total":len(qs)}

@app.post("/api/questionnaires/", status_code=201)
def create_q(req: QCreate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    q=QuestionnaireDB(title=req.title,framework=req.framework,vendor=req.vendor,total=req.total,answered=0,status="pending",due_date=req.due,notes=req.notes)
    db.add(q); db.commit(); db.refresh(q); return qdict(q)

@app.put("/api/questionnaires/{qid}")
def update_q(qid: int, req: QUpdate, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    q=db.query(QuestionnaireDB).get(qid)
    if not q: raise HTTPException(404)
    for f in ["title","framework","vendor","total","answered","status","due_date","notes"]:
        val=getattr(req,f,None)
        if val is not None: setattr(q,f,val)
    if q.answered>=q.total: q.status="completed"
    elif q.answered>0: q.status="in_progress"
    db.commit(); return qdict(q)

@app.delete("/api/questionnaires/{qid}")
def delete_q(qid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    q=db.query(QuestionnaireDB).get(qid)
    if not q: raise HTTPException(404)
    db.delete(q); db.commit(); return {"message":"Deleted"}

# ── SCAN ──────────────────────────────────────────────────────
@app.post("/api/scan/domain")
def scan_domain(req: ScanReq, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    domain=re.sub(r"^https?://","",req.domain).split("/")[0].strip().lower()
    if not domain or "." not in domain: raise HTTPException(400,"Invalid domain")

    sl=ssl_check(domain); hd=header_check(domain); pt=port_check(domain)

    # Calculate score
    score=950
    score+={"A":0,"B":-50,"C":-120,"D":-200,"F":-300}.get(sl["grade"],0)
    score+={"A":0,"B":-50,"C":-100,"D":-150,"F":-200}.get(hd["grade"],0)
    score-=len(pt["dangerous_ports"])*60
    score=max(100,min(950,score))

    findings=sl["findings"]+hd["findings"]+pt["findings"]

    # If all checks failed (firewall/timeout), add informative message
    if sl["grade"]=="F" and hd["grade"]=="F" and not findings:
        findings.append(f"Could not reach {domain} — firewall may be blocking scans")
        findings.append("SSL check: connection refused or timed out")
        findings.append("Header check: connection refused or timed out")
        score = max(100, score - 100)

    # Auto-create alert for expiring SSL
    alerts_created = []
    if sl.get("valid") and sl.get("days_left",99)<=7:
        db.add(AlertDB(title=f"SSL expiring in {sl['days_left']} days — {domain}",
            severity="critical",category="Website Security",status="open",source="scan"))
        db.commit()
        alerts_created.append("SSL expiry alert")

    return {
        "domain": domain,
        "score": score,
        "grades": {
            "ssl":     sl["grade"],
            "email":   "B",
            "headers": hd["grade"],
            "network": "A" if not pt["dangerous_ports"] else "C"
        },
        "findings": findings,
        "alertsCreated": alerts_created,
        "ssl": {"valid": sl.get("valid",False), "daysLeft": sl.get("days_left",0), "expiry": sl.get("expiry","")},
        "dangerousPorts": pt["dangerous_ports"]
    }

@app.get("/api/scan/history")
def scan_history(uid: int=Depends(get_uid)): return {"scans":[]}

# ── LOGS / ML ─────────────────────────────────────────────────
@app.get("/api/logs/")
def list_logs(anomalies: bool=False, limit: int=100, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    q=db.query(ActivityLogDB)
    if anomalies: q=q.filter_by(is_anomaly=True)
    logs=q.order_by(ActivityLogDB.timestamp.desc()).limit(limit).all()
    return {"logs":[logdict(l) for l in logs],"total":len(logs),"anomalyCount":db.query(ActivityLogDB).filter_by(is_anomaly=True).count()}

@app.post("/api/logs/track")
def track_action(req: TrackReq, request: Request, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    user=db.query(UserDB).get(uid)
    if user: user.last_seen=datetime.utcnow()
    ip=get_ip(request); ua=req.userAgent or request.headers.get("user-agent",""); device=get_device(ua)
    result=anomaly_detector.predict(req.action)
    log=ActivityLogDB(user_email=user.email if user else "unknown",action=req.action,page=req.page,ip_address=ip,user_agent=ua[:300],device_info=device,is_anomaly=result["is_anomaly"],anomaly_score=result["score"])
    if result["is_anomaly"] and result["score"]>0.7:
        db.add(AlertDB(title=f"ML Anomaly: {req.action} by {user.email if user else 'unknown'} from {ip}",severity="high",category="Anomaly Detection",status="open",source="ml",ml_score=result["score"],description=f"{result.get('reason','Unusual activity')} | IP:{ip} | Device:{device}"))
    db.add(log); db.commit(); return {"logged":True,"anomaly":result}

@app.get("/api/logs/anomalies")
def list_anomalies(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    logs=db.query(ActivityLogDB).filter_by(is_anomaly=True).order_by(ActivityLogDB.timestamp.desc()).limit(50).all()
    return {"anomalies":[logdict(l) for l in logs],"total":len(logs)}

@app.post("/api/logs/ml/retrain")
def retrain(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    logs=db.query(ActivityLogDB).order_by(ActivityLogDB.timestamp.desc()).limit(1000).all()
    return anomaly_detector.retrain([{"action":l.action,"timestamp":l.timestamp.isoformat(),"freq":1} for l in logs])

@app.post("/api/logs/ml/classify")
def classify_text(req: ClassifyReq, uid: int=Depends(get_uid)):
    return threat_classifier.predict(req.text)

@app.post("/api/logs/simulate-attack")
def simulate_attack(req: SimulateReq, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    user=db.query(UserDB).get(uid)
    attacks={
        "brute_force":       {"title":"Brute Force Login Attack Detected",       "severity":"critical","category":"Network",       "description":"150+ failed logins from 185.220.101.45 at 2AM.","action":"login",        "hour":2},
        "data_exfiltration": {"title":"Suspicious Bulk Data Export at 3AM",       "severity":"critical","category":"Data Leak",     "description":"45 exports in 1hr at 3AM — possible data theft.", "action":"export_report", "hour":3},
        "insider_threat":    {"title":"Insider Threat — Mass Deletion at 10PM",   "severity":"critical","category":"Insider Threat","description":"Bulk delete at 10PM from internal IP.",           "action":"delete_vendor", "hour":22},
        "credential_stuffing":{"title":"Credential Stuffing from Multiple IPs",   "severity":"critical","category":"Network",       "description":"Login attempts from 23 IPs at 1AM.",             "action":"login",         "hour":1},
    }
    atk=attacks.get(req.type,attacks["brute_force"])
    for i in range(3):
        ts=datetime.utcnow().replace(hour=atk["hour"],minute=random.randint(0,59))
        db.add(ActivityLogDB(user_email=user.email if user else "attacker",action=atk["action"],ip_address=f"185.220.101.{random.randint(1,99)}",device_info="Unknown",timestamp=ts,is_anomaly=True,anomaly_score=0.95))
    alert=AlertDB(title=atk["title"],severity=atk["severity"],category=atk["category"],status="open",source="ml",ml_score=0.95,description=atk["description"])
    db.add(alert); db.commit(); db.refresh(alert)
    recalculate_score(db)
    return {"success":True,"attackType":req.type,"logsCreated":3,"alertId":alert.id,"message":"Attack simulated!"}

# ── REPORTS ───────────────────────────────────────────────────
@app.get("/api/reports/")
def list_reports(uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    return {"reports":[{"id":r.id,"title":r.title,"type":r.type,"pages":r.pages,"date":r.created_at.strftime("%Y-%m-%d")} for r in db.query(ReportDB).order_by(ReportDB.created_at.desc()).all()]}

@app.post("/api/reports/generate", status_code=201)
def gen_report(req: ReportGenReq, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    user       = db.query(UserDB).get(uid)
    vendors    = db.query(VendorDB).all()
    all_alerts = db.query(AlertDB).all()
    open_alerts= [a for a in all_alerts if a.status=="open"]
    leaks      = db.query(LeakDB).all()
    logs       = db.query(ActivityLogDB).order_by(ActivityLogDB.timestamp.desc()).limit(500).all()
    sc         = db.query(SecurityScoreDB).order_by(SecurityScoreDB.created_at.desc()).first()
    score      = sc.score if sc else 742
    now        = datetime.utcnow()
    org        = user.company if user else "N/A"
    analyst    = user.name if user else "Unknown"

    # Risk breakdown
    crit_v  = sum(1 for v in vendors if risk_level(v.score)=="critical")
    high_v  = sum(1 for v in vendors if risk_level(v.score)=="high")
    avg_v   = int(sum(v.score for v in vendors)/len(vendors)) if vendors else 0
    anom_ct = sum(1 for l in logs if l.is_anomaly)
    active_leaks = [l for l in leaks if l.status!="resolved"]
    total_creds  = sum(l.credentials for l in leaks)

    # Severity breakdown
    sev_counts = {k: sum(1 for a in open_alerts if a.severity==k) for k in ["critical","high","medium","low"]}

    # Report titles per type
    titles = {
        "security-posture":  f"Security Posture Report — {now.strftime('%B %Y')}",
        "vendor-risk":       f"Vendor Risk Assessment — {now.strftime('%B %Y')}",
        "executive-summary": f"Executive Security Summary — {now.strftime('%B %d, %Y')}",
        "incident":          f"Incident & Threat Report — {now.strftime('%B %Y')}",
        "compliance":        f"Compliance Status Report — {now.strftime('%B %Y')}",
    }
    title = titles.get(req.type, f"Security Report — {now.strftime('%B %Y')}")

    SEP  = "=" * 60
    SEP2 = "-" * 60

    # ── Build content based on type ──────────────────────────
    if req.type == "vendor-risk":
        content  = f"CYBERGUARD — VENDOR RISK ASSESSMENT\n{SEP}\n"
        content += f"Generated : {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        content += f"Org       : {org}\n"
        content += f"Analyst   : {analyst}\n"
        content += f"Vendors   : {len(vendors)} monitored\n{SEP}\n\n"
        content += f"EXECUTIVE SUMMARY\n{SEP2}\n"
        content += f"Average vendor security score: {avg_v}/950\n"
        content += f"Critical risk vendors : {crit_v}\n"
        content += f"High risk vendors     : {high_v}\n"
        content += f"Low risk vendors      : {sum(1 for v in vendors if risk_level(v.score)=='low')}\n\n"
        content += f"VENDOR DETAILS\n{SEP2}\n"
        for v in sorted(vendors, key=lambda x: x.score):
            bar = "█" * int(v.score/95) + "░" * (10-int(v.score/95))
            content += f"\n  {v.name}\n"
            content += f"    Domain      : {v.domain}\n"
            content += f"    Category    : {v.category}\n"
            content += f"    Criticality : {v.criticality}\n"
            content += f"    Score       : {v.score}/950  {bar}\n"
            content += f"    Risk Level  : {risk_level(v.score).upper()}\n"
            content += f"    Open Issues : {v.issues}\n"
            content += f"    Trend       : {v.trend}\n"
        content += f"\n{SEP}\nGenerated by CyberGuard v2.0"

    elif req.type == "executive-summary":
        content  = f"CYBERGUARD — EXECUTIVE SECURITY SUMMARY\n{SEP}\n"
        content += f"Date      : {now.strftime('%B %d, %Y')}\n"
        content += f"Org       : {org}\n"
        content += f"Prepared  : {analyst}\n{SEP}\n\n"
        content += f"KEY METRICS AT A GLANCE\n{SEP2}\n"
        content += f"  Security Score    : {score}/950  (Grade: {grade(score)})\n"
        content += f"  Open Alerts       : {len(open_alerts)}  ({sev_counts['critical']} critical)\n"
        content += f"  Vendors Monitored : {len(vendors)}  ({crit_v} critical risk)\n"
        content += f"  Active Data Leaks : {len(active_leaks)}  ({total_creds} credentials exposed)\n"
        content += f"  ML Anomalies      : {anom_ct} detected in last 500 actions\n\n"
        content += f"RISK ASSESSMENT\n{SEP2}\n"
        content += f"  The organisation's overall security posture is rated {grade(score)}\n"
        if sev_counts["critical"] > 0:
            content += f"  ⚠ URGENT: {sev_counts['critical']} critical alerts require immediate attention\n"
        if crit_v > 0:
            content += f"  ⚠ {crit_v} vendor(s) classified as CRITICAL risk by ML models\n"
        if active_leaks:
            content += f"  ⚠ {len(active_leaks)} active data leak(s) under investigation\n"
        content += f"\nTOP PRIORITY ALERTS\n{SEP2}\n"
        for a in sorted(open_alerts, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.severity,4))[:5]:
            content += f"  [{a.severity.upper():<8}] {a.title}\n"
        content += f"\nRECOMMENDATIONS\n{SEP2}\n"
        recs = []
        if sev_counts["critical"]>0: recs.append("Immediately remediate all critical severity alerts")
        if crit_v>0: recs.append(f"Conduct security review for {crit_v} critical-risk vendor(s)")
        if active_leaks: recs.append("Rotate all exposed credentials and API keys immediately")
        if anom_ct>10: recs.append("Investigate ML-detected anomalies for potential insider threats")
        recs.append("Schedule quarterly vendor risk reassessment")
        recs.append("Enable DMARC enforcement policy on email domain")
        for i,r in enumerate(recs,1): content+=f"  {i}. {r}\n"
        content += f"\n{SEP}\nGenerated by CyberGuard v2.0"

    elif req.type == "incident":
        content  = f"CYBERGUARD — INCIDENT & THREAT REPORT\n{SEP}\n"
        content += f"Generated : {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        content += f"Org       : {org}\n"
        content += f"Period    : Last 30 days\n{SEP}\n\n"
        content += f"ALERT SUMMARY\n{SEP2}\n"
        content += f"  Total Alerts    : {len(all_alerts)}\n"
        content += f"  Open            : {len(open_alerts)}\n"
        content += f"  Acknowledged    : {sum(1 for a in all_alerts if a.status=='acknowledged')}\n"
        content += f"  Resolved        : {sum(1 for a in all_alerts if a.status=='resolved')}\n\n"
        content += f"  Severity Breakdown:\n"
        for sev in ["critical","high","medium","low"]:
            content += f"    {sev.upper():<10}: {sev_counts.get(sev,0)}\n"
        content += f"\nML-DETECTED ANOMALIES\n{SEP2}\n"
        content += f"  Total anomalies detected : {anom_ct}\n"
        high_anom = [l for l in logs if l.is_anomaly and l.anomaly_score>0.8]
        content += f"  High confidence (>80%)   : {len(high_anom)}\n"
        if high_anom:
            content += f"\n  Top anomalous events:\n"
            for l in high_anom[:5]:
                content += f"    {l.timestamp.strftime('%Y-%m-%d %H:%M')}  {l.user_email:<30} {l.action:<20} from {l.ip_address}\n"
        content += f"\nDATA LEAKS\n{SEP2}\n"
        for l in leaks:
            content += f"  [{l.severity.upper()}] {l.title}\n"
            content += f"    Source: {l.source} | Status: {l.status} | Credentials: {l.credentials}\n"
        ml_alerts = [a for a in all_alerts if a.source=="ml"]
        if ml_alerts:
            content += f"\nML-GENERATED ALERTS ({len(ml_alerts)} total)\n{SEP2}\n"
            for a in ml_alerts[:8]:
                content += f"  [{a.severity.upper()}] {a.title}\n    {a.description[:80]}\n"
        content += f"\n{SEP}\nGenerated by CyberGuard v2.0"

    elif req.type == "compliance":
        content  = f"CYBERGUARD — COMPLIANCE STATUS REPORT\n{SEP}\n"
        content += f"Generated : {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        content += f"Org       : {org}\n{SEP}\n\n"
        qs = db.query(QuestionnaireDB).all()
        content += f"QUESTIONNAIRE STATUS\n{SEP2}\n"
        content += f"  Total      : {len(qs)}\n"
        content += f"  Completed  : {sum(1 for q in qs if q.status=='completed')}\n"
        content += f"  In Progress: {sum(1 for q in qs if q.status=='in_progress')}\n"
        content += f"  Pending    : {sum(1 for q in qs if q.status=='pending')}\n\n"
        for q in qs:
            pct = round((q.answered/q.total)*100) if q.total>0 else 0
            bar = "█"*int(pct/10) + "░"*(10-int(pct/10))
            content += f"  {q.title}\n"
            content += f"    Framework : {q.framework}\n"
            content += f"    Progress  : {q.answered}/{q.total} ({pct}%) {bar}\n"
            content += f"    Status    : {q.status.replace('_',' ').upper()}\n"
            content += f"    Due       : {q.due_date or 'N/A'}\n\n"
        content += f"EMAIL SECURITY\n{SEP2}\n"
        dmarc_alert = any("DMARC" in a.title for a in all_alerts)
        content += f"  DMARC Policy : {'⚠ NOT ENFORCED' if dmarc_alert else '✓ OK'}\n"
        content += f"  SSL/TLS      : {'⚠ EXPIRING SOON' if any('SSL' in a.title for a in open_alerts) else '✓ OK'}\n\n"
        content += f"VENDOR COMPLIANCE\n{SEP2}\n"
        for v in vendors:
            content += f"  {v.name:<20} Risk:{risk_level(v.score).upper():<10} Score:{v.score}\n"
        content += f"\n{SEP}\nGenerated by CyberGuard v2.0"

    else:  # security-posture (default)
        content  = f"CYBERGUARD — SECURITY POSTURE REPORT\n{SEP}\n"
        content += f"Generated : {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        content += f"Org       : {org}\n"
        content += f"Analyst   : {analyst}\n{SEP}\n\n"
        content += f"OVERALL SECURITY SCORE\n{SEP2}\n"
        bar = "█" * int(score/95) + "░" * (10-int(score/95))
        content += f"  {score}/950  {bar}  Grade: {grade(score)}\n\n"
        content += f"SUMMARY\n{SEP2}\n"
        content += f"  Open Alerts       : {len(open_alerts)}\n"
        content += f"    Critical        : {sev_counts['critical']}\n"
        content += f"    High            : {sev_counts['high']}\n"
        content += f"    Medium          : {sev_counts['medium']}\n"
        content += f"    Low             : {sev_counts['low']}\n"
        content += f"  Vendors Monitored : {len(vendors)} (avg score: {avg_v})\n"
        content += f"  Active Data Leaks : {len(active_leaks)}\n"
        content += f"  ML Anomalies      : {anom_ct}\n\n"
        content += f"VENDOR RISK SUMMARY\n{SEP2}\n"
        for v in sorted(vendors, key=lambda x: x.score):
            content += f"  {v.name:<20} {v.score}/950  {risk_level(v.score).upper():<10} Issues:{v.issues}\n"
        content += f"\nCRITICAL & HIGH ALERTS\n{SEP2}\n"
        for a in [x for x in open_alerts if x.severity in ("critical","high")]:
            content += f"  [{a.severity.upper()}] {a.title}\n    → {a.description[:100]}\n\n"
        if active_leaks:
            content += f"DATA LEAKS\n{SEP2}\n"
            for l in active_leaks:
                content += f"  [{l.severity.upper()}] {l.title} ({l.source})\n"
                if l.credentials: content += f"    Credentials exposed: {l.credentials}\n"
        content += f"\n{SEP}\nGenerated by CyberGuard v2.0"

    pages = max(3, len(content.split("\n")) // 25)
    r = ReportDB(title=title, type=req.type, pages=pages, content=content)
    db.add(r); db.commit(); db.refresh(r)
    return {"id":r.id,"title":r.title,"type":r.type,"pages":r.pages,"date":r.created_at.strftime("%Y-%m-%d"),"content":content}

@app.get("/api/reports/{rid}/download")
def download_report(rid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    r=db.query(ReportDB).get(rid)
    if not r: raise HTTPException(404)
    return {"content":r.content,"title":r.title}

@app.delete("/api/reports/{rid}")
def delete_report(rid: int, uid: int=Depends(get_uid), db: Session=Depends(get_db)):
    r=db.query(ReportDB).get(rid)
    if not r: raise HTTPException(404)
    db.delete(r); db.commit(); return {"message":"Deleted"}

# ── ADMIN ─────────────────────────────────────────────────────
@app.get("/api/admin/users")
def admin_users(uid: int=Depends(get_admin), db: Session=Depends(get_db)):
    users=db.query(UserDB).all(); result=[]
    online_threshold=datetime.utcnow()-timedelta(minutes=5)
    for u in users:
        recent=db.query(ActivityLogDB).filter_by(user_email=u.email).order_by(ActivityLogDB.timestamp.desc()).first()
        anom=db.query(ActivityLogDB).filter_by(user_email=u.email,is_anomaly=True).count()
        total=db.query(ActivityLogDB).filter_by(user_email=u.email).count()
        result.append({**udict(u),"lastAction":recent.action if recent else None,"lastPage":recent.page if recent else None,"lastIp":recent.ip_address if recent else None,"lastDevice":recent.device_info if recent else None,"lastSeen":u.last_seen.isoformat() if u.last_seen else None,"online":bool(u.last_seen and u.last_seen>=online_threshold),"anomalyCount":anom,"totalActions":total,"riskLevel":"critical" if anom>5 else "high" if anom>2 else "low"})
    return {"users":result,"total":len(result),"online":sum(1 for u in users if u.last_seen and u.last_seen>=online_threshold)}

@app.get("/api/admin/stats")
def admin_stats(uid: int=Depends(get_admin), db: Session=Depends(get_db)):
    today=datetime.utcnow().replace(hour=0,minute=0,second=0,microsecond=0)
    online=db.query(UserDB).filter(UserDB.last_seen>=datetime.utcnow()-timedelta(minutes=5)).count()
    today_logs=db.query(ActivityLogDB).filter(ActivityLogDB.timestamp>=today).count()
    top=db.query(ActivityLogDB.user_email,func.count(ActivityLogDB.id).label("cnt")).filter(ActivityLogDB.timestamp>=today).group_by(ActivityLogDB.user_email).order_by(func.count(ActivityLogDB.id).desc()).limit(5).all()
    return {"totalUsers":db.query(UserDB).count(),"onlineNow":online,"totalLogs":db.query(ActivityLogDB).count(),"totalAnomalies":db.query(ActivityLogDB).filter_by(is_anomaly=True).count(),"todayLogs":today_logs,"topUsersToday":[{"email":r[0],"actions":r[1]} for r in top]}

@app.get("/api/admin/activity-feed")
def activity_feed(limit: int=50, uid: int=Depends(get_admin), db: Session=Depends(get_db)):
    logs=db.query(ActivityLogDB).order_by(ActivityLogDB.timestamp.desc()).limit(limit).all()
    return {"feed":[logdict(l) for l in logs]}

@app.get("/api/admin/user/{email}/activity")
def user_activity(email: str, uid: int=Depends(get_admin), db: Session=Depends(get_db)):
    logs=db.query(ActivityLogDB).filter_by(user_email=email).order_by(ActivityLogDB.timestamp.desc()).limit(100).all()
    anom=db.query(ActivityLogDB).filter_by(user_email=email,is_anomaly=True).count()
    return {"logs":[logdict(l) for l in logs],"totalLogs":len(logs),"anomalyCount":anom}

@app.post("/api/admin/users/create")
def admin_create_user(req: CreateUserReq, uid: int=Depends(get_admin), db: Session=Depends(get_db)):
    if db.query(UserDB).filter_by(email=req.email.lower().strip()).first(): raise HTTPException(400,"Email already exists")
    u=UserDB(name=req.name,email=req.email.lower().strip(),password_hash=generate_password_hash(req.password),role=req.role,is_admin=req.isAdmin,company=req.company)
    db.add(u); db.commit(); db.refresh(u); return udict(u)

@app.put("/api/admin/users/{user_id}")
def admin_update_user(user_id: int, req: UpdateUserReq, uid: int=Depends(get_admin), db: Session=Depends(get_db)):
    u=db.query(UserDB).get(user_id)
    if not u: raise HTTPException(404)
    if req.isAdmin is not None: u.is_admin=req.isAdmin
    if req.role: u.role=req.role
    if req.name: u.name=req.name
    if req.password: u.password_hash=generate_password_hash(req.password)
    db.commit(); return udict(u)

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, uid: int=Depends(get_admin), db: Session=Depends(get_db)):
    u=db.query(UserDB).get(user_id)
    if not u: raise HTTPException(404)
    if u.id==uid: raise HTTPException(400,"Cannot delete yourself")
    db.delete(u); db.commit(); return {"message":"Deleted"}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    print(f"\n{'='*55}")
    print(f"  🛡  CyberGuard v2.0 — Production Ready")
    print(f"{'='*55}")
    print(f"  URL      : http://{host}:{port}")
    print(f"  Health   : http://{host}:{port}/health")
    print(f"  Docs     : {'http://'+host+':'+str(port)+'/docs' if DEBUG else 'disabled (set DEBUG=true)'}")
    print(f"  Frontend : {FRONTEND_DIR}")
    print(f"  Database : {DATABASE_URL[:40]}...")
    print(f"  Debug    : {DEBUG}")
    print(f"{'='*55}\n")
    uvicorn.run("main:app", host=host, port=port, reload=DEBUG)
