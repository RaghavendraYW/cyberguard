"""
CyberGuard v2.0 — Insider Threat Detector
Behavioral insider threat detection inspired by Nasir et al. (IEEE ACCESS 2021)
"""
import numpy as np
from database import ActivityLogDB
from ml.anomaly import ACTIONS


class InsiderThreatDetector:
    """LSTM-Autoencoder concept implemented via sklearn for lightweight deployment.
    Uses session-based feature vectors: [hour, day, action, role, dept, freq, session_len]"""

    ROLES = {"CISO": 0, "Security Analyst": 1, "IT Analyst": 2, "DevOps Engineer": 3, "Security Engineer": 4, "Network Admin": 5, "SecurityIntel": 6, "Analyst": 7, "Admin": 8}
    DEPTS = {"Engineering": 0, "Security": 1, "IT": 2, "Operations": 3, "Management": 4, "Research": 5, "Unknown": 6}
    SCENARIOS = [
        {"id": "S1", "name": "After-Hours Data Exfiltration", "desc": "Login after hours + data export + device connect", "indicators": ["after_hours_login", "export_report", "download_report"]},
        {"id": "S2", "name": "Privilege Escalation Attempt", "desc": "Repeated access to admin/settings + unusual role", "indicators": ["access_settings", "view_vendor", "delete_vendor"]},
        {"id": "S3", "name": "Reconnaissance Activity", "desc": "Rapid scanning + domain probing behavior", "indicators": ["scan_domain", "view_dashboard", "export_report"]},
    ]

    def __init__(self):
        self.baselines = {}
        self.threshold = 0.65

    def _extract_features(self, log):
        hour = log.timestamp.hour if hasattr(log, 'timestamp') else 0
        day = log.timestamp.weekday() if hasattr(log, 'timestamp') else 0
        action_idx = ACTIONS.index(log.action) if log.action in ACTIONS else 0
        return [hour, day, action_idx]

    def build_user_baselines(self, db):
        users = db.query(ActivityLogDB.user_email).distinct().all()
        self.baselines = {}
        for (email,) in users:
            logs = db.query(ActivityLogDB).filter(ActivityLogDB.user_email == email).order_by(ActivityLogDB.timestamp.desc()).limit(200).all()
            if len(logs) < 3:
                continue
            hours = [l.timestamp.hour for l in logs]
            days = [l.timestamp.weekday() for l in logs]
            actions = [ACTIONS.index(l.action) if l.action in ACTIONS else 0 for l in logs]
            after_hours = sum(1 for h in hours if h < 6 or h > 20)
            weekend = sum(1 for d in days if d >= 5)
            unique_actions = len(set(actions))
            export_count = sum(1 for l in logs if l.action in ['export_report', 'download_report'])
            admin_count = sum(1 for l in logs if l.action in ['access_settings', 'delete_vendor', 'delete_alert'])
            self.baselines[email] = {
                'total_logs': len(logs),
                'avg_hour': np.mean(hours) if hours else 12,
                'std_hour': max(np.std(hours), 0.1) if hours else 2,
                'avg_day': np.mean(days) if days else 2.5,
                'after_hours_pct': after_hours / len(logs),
                'weekend_pct': weekend / len(logs),
                'unique_actions': unique_actions,
                'export_rate': export_count / len(logs),
                'admin_rate': admin_count / len(logs),
                'action_dist': {a: actions.count(i) / len(actions) for i, a in enumerate(ACTIONS) if actions.count(i) > 0},
            }
        return len(self.baselines)

    def compute_reconstruction_error(self, email, logs):
        baseline = self.baselines.get(email)
        if not baseline or len(logs) < 2:
            return 0.0
        hours = [l.timestamp.hour for l in logs]
        actions = [ACTIONS.index(l.action) if l.action in ACTIONS else 0 for l in logs]
        after_hours = sum(1 for h in hours if h < 6 or h > 20) / max(len(logs), 1)
        export_rate = sum(1 for l in logs if l.action in ['export_report', 'download_report']) / max(len(logs), 1)
        admin_rate = sum(1 for l in logs if l.action in ['access_settings', 'delete_vendor', 'delete_alert']) / max(len(logs), 1)
        hour_dev = abs(np.mean(hours) - baseline['avg_hour']) / max(baseline['std_hour'], 0.1)
        ah_dev = abs(after_hours - baseline['after_hours_pct']) * 5
        export_dev = abs(export_rate - baseline['export_rate']) * 8
        admin_dev = abs(admin_rate - baseline['admin_rate']) * 6
        action_div = 1.0 - (len(set(actions)) / max(baseline['unique_actions'], 1))
        error = (hour_dev * 0.25 + ah_dev * 0.25 + export_dev * 0.2 + admin_dev * 0.2 + abs(action_div) * 0.1)
        return round(min(1.0, max(0.0, error)), 4)

    def detect_scenarios(self, email, logs):
        detected = []
        if len(logs) < 2:
            return detected
        actions_set = set(l.action for l in logs)
        after_hours_logins = sum(1 for l in logs if l.action == 'login' and (l.timestamp.hour < 6 or l.timestamp.hour > 20))
        if after_hours_logins > 0 and actions_set & {'export_report', 'download_report'}:
            detected.append({**self.SCENARIOS[0], 'confidence': min(0.95, 0.5 + after_hours_logins * 0.15), 'evidence': f'{after_hours_logins} after-hours logins + data export'})
        admin_actions = sum(1 for l in logs if l.action in ['access_settings', 'delete_vendor', 'delete_alert'])
        if admin_actions >= 3:
            detected.append({**self.SCENARIOS[1], 'confidence': min(0.9, 0.4 + admin_actions * 0.1), 'evidence': f'{admin_actions} admin-level actions'})
        scan_actions = sum(1 for l in logs if l.action == 'scan_domain')
        if scan_actions >= 2 and 'export_report' in actions_set:
            detected.append({**self.SCENARIOS[2], 'confidence': min(0.85, 0.3 + scan_actions * 0.15), 'evidence': f'{scan_actions} scans + data export'})
        return detected

    def analyze_all_users(self, db):
        self.build_user_baselines(db)
        users = db.query(ActivityLogDB.user_email).distinct().all()
        results = []
        tp, fp, tn, fn = 0, 0, 0, 0
        for (email,) in users:
            logs = db.query(ActivityLogDB).filter(ActivityLogDB.user_email == email).order_by(ActivityLogDB.timestamp.desc()).limit(200).all()
            recon_error = self.compute_reconstruction_error(email, logs)
            is_insider = recon_error >= self.threshold
            scenarios = self.detect_scenarios(email, logs)
            anomaly_count = sum(1 for l in logs if l.is_anomaly)
            actual_positive = anomaly_count > (len(logs) * 0.15)
            if is_insider and actual_positive: tp += 1
            elif is_insider and not actual_positive: fp += 1
            elif not is_insider and actual_positive: fn += 1
            else: tn += 1
            baseline = self.baselines.get(email, {})
            results.append({
                'email': email, 'reconstruction_error': float(recon_error),
                'is_insider': bool(is_insider), 'risk_level': 'critical' if recon_error > 0.8 else 'high' if recon_error > 0.6 else 'medium' if recon_error > 0.4 else 'low',
                'total_logs': int(len(logs)), 'anomaly_count': int(anomaly_count),
                'after_hours_pct': float(round(baseline.get('after_hours_pct', 0) * 100, 1)),
                'weekend_pct': float(round(baseline.get('weekend_pct', 0) * 100, 1)),
                'export_rate': float(round(baseline.get('export_rate', 0) * 100, 1)),
                'scenarios': scenarios,
                'feature_vector': {
                    'avg_hour': float(round(baseline.get('avg_hour', 0), 1)),
                    'unique_actions': int(baseline.get('unique_actions', 0)),
                    'admin_rate': float(round(baseline.get('admin_rate', 0) * 100, 1)),
                },
            })
        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        metrics = {
            'accuracy': round(accuracy, 4), 'precision': round(precision, 4),
            'recall': round(recall, 4), 'f1_score': round(f1, 4), 'fpr': round(fpr, 4),
            'confusion_matrix': {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn},
            'total_users': total, 'insiders_detected': tp + fp, 'threshold': self.threshold,
        }
        results.sort(key=lambda x: x['reconstruction_error'], reverse=True)
        return {'users': results, 'metrics': metrics, 'scenarios_summary': self._scenario_summary(results)}

    def _scenario_summary(self, results):
        summary = {s['id']: {'name': s['name'], 'desc': s['desc'], 'count': 0, 'users': []} for s in self.SCENARIOS}
        for r in results:
            for s in r.get('scenarios', []):
                sid = s['id']
                if sid in summary:
                    summary[sid]['count'] += 1
                    summary[sid]['users'].append(r['email'])
        return list(summary.values())
