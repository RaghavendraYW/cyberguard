"""
CyberGuard v2.0 — Anomaly Detector (Isolation Forest)
"""
import os
import joblib
import numpy as np
from datetime import datetime

from config import ML_DIR

ACTIONS = ["login", "logout", "view_dashboard", "export_report", "add_vendor", "delete_vendor",
           "delete_alert", "scan_domain", "access_settings", "view_vendor", "update_alert", "download_report"]


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.trained = False
        path = os.path.join(ML_DIR, "anomaly.joblib")
        if os.path.exists(path):
            self.model = joblib.load(path)
            self.trained = True
        else:
            self._train(path)

    def _train(self, path):
        try:
            from sklearn.ensemble import IsolationForest
            rng = np.random.RandomState(42)
            n = 500
            X_n = np.column_stack([rng.randint(8, 19, n), rng.randint(0, 5, n), rng.randint(0, len(ACTIONS), n), rng.randint(1, 10, n)])
            ha = np.concatenate([rng.randint(0, 6, 25), rng.randint(22, 24, 25)])
            da = rng.randint(0, 7, 50)
            X_a = np.column_stack([ha, da, rng.randint(0, len(ACTIONS), 50), rng.randint(50, 200, 50)])
            self.model = IsolationForest(n_estimators=200, contamination=0.08, random_state=42)
            self.model.fit(np.vstack([X_n, X_a]))
            self.trained = True
            joblib.dump(self.model, path)
            print("✅ Anomaly detector trained")
        except Exception as e:
            print(f"⚠ Anomaly: {e}")

    def predict(self, action, hour=None):
        if not self.trained:
            return {"is_anomaly": False, "score": 0.0, "reason": ""}
        if hour is None:
            hour = datetime.utcnow().hour
        day = datetime.utcnow().weekday()
        act = ACTIONS.index(action) if action in ACTIONS else 0
        X = np.array([[hour, day, act, 1]])
        pred = self.model.predict(X)[0]
        score = max(0.0, min(1.0, 1.0 - (float(self.model.score_samples(X)[0]) + 0.5)))
        reasons = []
        if hour < 6 or hour > 22:
            reasons.append(f"Unusual hour ({hour:02d}:00)")
        if day >= 5:
            reasons.append("Weekend activity")
        return {"is_anomaly": pred == -1, "score": round(score, 3), "reason": "; ".join(reasons) or "Normal"}

    def retrain(self, logs):
        if len(logs) < 50:
            return {"status": "insufficient_data", "count": len(logs)}
        try:
            from sklearn.ensemble import IsolationForest
            X = []
            for l in logs:
                ts = datetime.fromisoformat(l["timestamp"])
                act = ACTIONS.index(l["action"]) if l["action"] in ACTIONS else 0
                X.append([ts.hour, ts.weekday(), act, l.get("freq", 1)])
            self.model = IsolationForest(n_estimators=200, contamination=0.08, random_state=42)
            self.model.fit(np.array(X))
            self.trained = True
            path = os.path.join(ML_DIR, "anomaly.joblib")
            joblib.dump(self.model, path)
            return {"status": "retrained", "samples": len(X)}
        except Exception as e:
            return {"status": "error", "detail": str(e)}
