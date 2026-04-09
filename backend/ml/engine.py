"""
CyberGuard v2.0 — ML Engine
Instantiates all ML models and provides ml_summary().
"""
from ml.anomaly import AnomalyDetector
from ml.vendor import VendorRiskScorer
from ml.threat import ThreatClassifier
from ml.insider import InsiderThreatDetector

# Initialize all ML models
anomaly_detector   = AnomalyDetector()
vendor_risk_scorer = VendorRiskScorer()
threat_classifier  = ThreatClassifier()
insider_detector   = InsiderThreatDetector()


def ml_summary():
    return {
        "anomalyDetector":  {"status": "active" if anomaly_detector.trained  else "disabled", "model": "Isolation Forest",    "description": "Detects unusual behaviour patterns"},
        "vendorRiskScorer": {"status": "active" if vendor_risk_scorer.trained else "disabled", "model": "Random Forest",       "description": "Predicts vendor risk level"},
        "threatClassifier": {"status": "active" if threat_classifier.trained  else "disabled", "model": "Naive Bayes + TF-IDF","description": "Classifies threat text"},
        "insiderDetector":  {"status": "active",                                               "model": "LSTM-AE (sklearn)",   "description": "Behavioral insider threat detection — Nasir et al."},
    }
