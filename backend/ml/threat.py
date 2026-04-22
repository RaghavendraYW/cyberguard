"""
CyberGuard v2.0 — Threat Classifier (Naive Bayes + TF-IDF)
"""
import os
import joblib
from config import ML_DIR


class ThreatClassifier:
    LABELS = ["benign", "suspicious", "phishing", "malware"]

    def __init__(self):
        self.model = None
        self.vec = None
        self.trained = False
        mp = os.path.join(ML_DIR, "threat.joblib")
        vp = os.path.join(ML_DIR, "threat_vec.joblib")
        if os.path.exists(mp) and os.path.exists(vp):
            self.model = joblib.load(mp)
            self.vec = joblib.load(vp)
            self.trained = True
        else:
            self._train(mp, vp)

    def _train(self, mp, vp):
        try:
            from sklearn.naive_bayes import MultinomialNB
            from sklearn.feature_extraction.text import TfidfVectorizer
            data = [
                ("user logged in successfully", 0), ("weekly report generated", 0), ("scan completed", 0), ("dashboard viewed", 0), ("settings saved", 0),
                ("multiple failed login attempts", 1), ("unusual access at 3am unknown IP", 1), ("large data export midnight", 1), ("access from tor node", 1), ("bulk delete performed", 1),
                ("click here verify account credentials", 2), ("account suspended reset password immediately", 2), ("urgent invoice payment click link", 2), ("IT password reset required", 2), ("bank account suspended", 2),
                ("ransomware detected files encrypted", 3), ("trojan found in download", 3), ("keylogger detected workstation", 3), ("malicious script injected", 3), ("rootkit system compromised", 3)
            ]
            texts, labels = zip(*data)
            self.vec = TfidfVectorizer(ngram_range=(1, 2), max_features=500)
            X = self.vec.fit_transform(texts)
            self.model = MultinomialNB(alpha=0.1)
            self.model.fit(X, list(labels))
            self.trained = True
            joblib.dump(self.model, mp)
            joblib.dump(self.vec, vp)
            print("✅ Threat classifier trained")
        except Exception as e:
            print(f"⚠ Classifier: {e}")

    def predict(self, text):
        if not self.trained:
            return {"label": "unknown", "confidence": 0.5, "ml_enabled": False, "probabilities": {}}
        try:
            X = self.vec.transform([text.lower()])
            pred = self.model.predict(X)[0]
            proba = self.model.predict_proba(X)[0]
            return {"label": self.LABELS[pred], "confidence": round(float(proba[pred]), 3), "ml_enabled": True, "probabilities": {self.LABELS[i]: round(float(p), 3) for i, p in enumerate(proba)}}
        except Exception:
            return {"label": "unknown", "confidence": 0.5, "ml_enabled": False, "probabilities": {}}
