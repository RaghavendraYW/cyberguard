"""
CyberGuard v2.0 — Insider Threat Detection Routes (Nasir et al. IEEE ACCESS 2021)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, ActivityLogDB
from auth import get_uid
from ml.engine import insider_detector
from ml.anomaly import ACTIONS

router = APIRouter(prefix="/api/insider", tags=["insider"])


@router.get("/analyze")
def insider_analyze(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Run full insider threat analysis across all users"""
    return insider_detector.analyze_all_users(db)


@router.get("/user/{email}/profile")
def insider_user_profile(email: str, uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Get behavioral profile for a specific user"""
    insider_detector.build_user_baselines(db)
    logs = db.query(ActivityLogDB).filter(ActivityLogDB.user_email == email).order_by(ActivityLogDB.timestamp.desc()).limit(200).all()
    if not logs:
        raise HTTPException(404, "No logs found for user")
    recon_error = insider_detector.compute_reconstruction_error(email, logs)
    scenarios = insider_detector.detect_scenarios(email, logs)
    baseline = insider_detector.baselines.get(email, {})
    # Session analysis
    sessions = []
    current_session = []
    for log in reversed(logs):
        current_session.append({'action': log.action, 'time': log.timestamp.isoformat(), 'anomaly': log.is_anomaly})
        if log.action == 'logout' or len(current_session) >= 20:
            sessions.append(current_session)
            current_session = []
    if current_session:
        sessions.append(current_session)
    return {
        'email': email, 'reconstruction_error': float(recon_error),
        'is_insider': bool(recon_error >= insider_detector.threshold),
        'risk_level': 'critical' if recon_error > 0.8 else 'high' if recon_error > 0.6 else 'medium' if recon_error > 0.4 else 'low',
        'total_logs': int(len(logs)), 'anomaly_count': int(sum(1 for l in logs if l.is_anomaly)),
        'baseline': baseline, 'scenarios': scenarios,
        'sessions': sessions[:10],
        'feature_vector': {
            'avg_hour': float(round(baseline.get('avg_hour', 0), 1)),
            'std_hour': float(round(baseline.get('std_hour', 0), 1)),
            'unique_actions': int(baseline.get('unique_actions', 0)),
            'after_hours_pct': float(round(baseline.get('after_hours_pct', 0) * 100, 1)),
            'weekend_pct': float(round(baseline.get('weekend_pct', 0) * 100, 1)),
            'export_rate': float(round(baseline.get('export_rate', 0) * 100, 1)),
            'admin_rate': float(round(baseline.get('admin_rate', 0) * 100, 1)),
        },
        'activity_timeline': [{'action': l.action, 'hour': l.timestamp.hour, 'day': l.timestamp.strftime('%a'), 'anomaly': bool(l.is_anomaly), 'score': float(l.anomaly_score or 0)} for l in logs[:50]],
    }


@router.get("/metrics")
def insider_metrics(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Get model performance metrics"""
    result = insider_detector.analyze_all_users(db)
    return result['metrics']


@router.get("/scenarios")
def insider_scenarios(uid: int = Depends(get_uid), db: Session = Depends(get_db)):
    """Get detected insider threat scenarios"""
    result = insider_detector.analyze_all_users(db)
    all_scenarios = []
    for u in result['users']:
        for s in u.get('scenarios', []):
            all_scenarios.append({**s, 'user': u['email'], 'recon_error': u['reconstruction_error']})
    all_scenarios.sort(key=lambda x: x.get('confidence', 0), reverse=True)
    return {'scenarios': all_scenarios, 'summary': result['scenarios_summary']}
