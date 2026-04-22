"""
CyberGuard v2.0 — Vendor Risk Scorer (Random Forest)
"""
import os
import joblib
import numpy as np
from config import ML_DIR


class VendorRiskScorer:
    CRITS = ["Low", "Medium", "High", "Critical"]
    CATS = ["SaaS", "Cloud Infrastructure", "CRM", "Communication", "Payment Processing", "HR Software", "Security", "Analytics", "Other"]
    RISKS = ["low", "medium", "high", "critical"]

    def __init__(self):
        self.model = None
        self.trained = False
        path = os.path.join(ML_DIR, "vendor.joblib")
        if os.path.exists(path):
            self.model = joblib.load(path)
            self.trained = True
        else:
            self._train(path)

    def _train(self, path):
        try:
            from sklearn.ensemble import RandomForestClassifier
            rng = np.random.RandomState(42)
            n = 600
            scores = rng.randint(200, 951, n)
            issues = rng.randint(0, 30, n)
            crits = rng.randint(0, 4, n)
            cats = rng.randint(0, len(self.CATS), n)
            labels = [0 if scores[i] >= 800 and issues[i] < 5 else 1 if scores[i] >= 650 and issues[i] < 12 else 2 if scores[i] >= 450 else 3 for i in range(n)]
            self.model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=8)
            self.model.fit(np.column_stack([scores, issues, crits, cats]), labels)
            self.trained = True
            joblib.dump(self.model, path)
            print("✅ Vendor risk scorer trained")
        except Exception as e:
            print(f"⚠ Vendor: {e}")

    def predict(self, v):
        s = v.get("score", 700)
        fallback = {"risk": "low" if s >= 800 else "medium" if s >= 650 else "high" if s >= 450 else "critical", "confidence": 0.7, "ml_enabled": False, "probabilities": {}}
        if not self.trained:
            return fallback
        try:
            crit = self.CRITS.index(v.get("criticality", "Medium")) if v.get("criticality") in self.CRITS else 1
            cat = self.CATS.index(v.get("category", "SaaS")) if v.get("category") in self.CATS else 0
            X = np.array([[s, v.get("issues", 0), crit, cat]])
            idx = self.model.predict(X)[0]
            proba = self.model.predict_proba(X)[0]
            return {"risk": self.RISKS[idx], "confidence": round(float(proba[idx]), 3), "ml_enabled": True, "probabilities": {self.RISKS[i]: round(float(p), 3) for i, p in enumerate(proba)}}
        except Exception:
            return fallback
