import urllib.request
import json
import sys

def run_tests():
    base = 'http://127.0.0.1:8000'
    print("========================================")
    print("CYBERGUARD E2E TEST SUITE")
    print("========================================")

    # 1. Test GET /
    print("\n1. Testing GET / (Login Page)")
    with urllib.request.urlopen(f"{base}/") as res:
        assert res.status == 200, f"Expected 200, got {res.status}"
        html = res.read().decode("utf-8")
        assert 'id="loginPage"' in html, "loginPage not found in HTML"
        assert 'value="Admin@1234"' not in html, "Hardcoded password found in HTML!"
        print("   [PASS] GET / serves loginPage securely without exposed credentials")

    # 2. Test GET /manifest.json
    print("\n2. Testing GET /manifest.json")
    with urllib.request.urlopen(f"{base}/manifest.json") as res:
        assert res.status == 200
        print("   [PASS] GET /manifest.json returned 200 OK")

    # 3. Test Login Variations
    print("\n3. Testing Legitimate Authentication and Rejection of Weak/Backdoor Attempts")
    
    # Negative tests: Weak/backdoor credentials must fail
    negative_tests = [
        ("admin@company.com", "password", "Default 'password' blocked"),
        ("admin", "admin", "Short backdoor 'admin' blocked"),
        ("admin@company.com", "wrongpass", "Wrong password blocked"),
    ]
    for ident, pw, label in negative_tests:
        req = urllib.request.Request(
            f"{base}/api/auth/login",
            data=json.dumps({"email": ident, "password": pw}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
        )
        try:
            with urllib.request.urlopen(req) as res:
                print(f"   [FAIL] {label}: Expected 401, but got {res.status}")
                sys.exit(1)
        except urllib.error.HTTPError as e:
            assert e.code == 401, f"Expected 401, got {e.code}"
            print(f"   [PASS] {label}: Correctly rejected (HTTP 401)")

    # Positive tests: Valid credentials succeed
    positive_tests = [
        ("admin@company.com", "Admin@1234", "Admin exact"),
        ("priya@company.com", "Analyst@1234", "Analyst account"),
        ("rahul@company.com", "Devops@1234", "DevOps account"),
    ]

    admin_token = None
    for ident, pw, label in positive_tests:
        req = urllib.request.Request(
            f"{base}/api/auth/login",
            data=json.dumps({"email": ident, "password": pw}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
        )
        try:
            with urllib.request.urlopen(req) as res:
                data = json.loads(res.read().decode("utf-8"))
                assert "token" in data, "Token missing in response"
                if label == "Admin exact":
                    admin_token = data["token"]
                print(f"   [PASS] {label}: Authenticated as {data['user']['name']} ({data['user']['role']})")
        except Exception as e:
            print(f"   [FAIL] {label}: {e}")
            sys.exit(1)

    # 4. Test Logout
    print("\n4. Testing Logout Flow")
    req_logout = urllib.request.Request(
        f"{base}/api/auth/logout",
        data=json.dumps({}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {admin_token}",
            "X-Requested-With": "XMLHttpRequest"
        }
    )
    with urllib.request.urlopen(req_logout) as res:
        assert res.status == 200
        print("   [PASS] POST /api/auth/logout returned 200 OK")

    # 5. Test Re-login immediately after logout
    print("\n5. Testing Re-login as Admin immediately after sign out")
    req_relogin = urllib.request.Request(
        f"{base}/api/auth/login",
        data=json.dumps({"email": "admin@company.com", "password": "Admin@1234"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
    )
    with urllib.request.urlopen(req_relogin) as res:
        assert res.status == 200
        relogin_data = json.loads(res.read().decode("utf-8"))
        admin_token = relogin_data["token"]
        print("   [PASS] Immediate re-login as Admin succeeded without invalid credentials error!")

    # 6. Test Protected API Endpoints across all modules
    print("\n6. Testing All Core App APIs End-to-End with Admin Token")
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "X-Requested-With": "XMLHttpRequest"
    }
    endpoints = [
        ("/api/dashboard/summary", "Dashboard Summary"),
        ("/api/vendors/?limit=10&skip=0", "Vendor Risk Table"),
        ("/api/vendors/stats", "Vendor Risk Stats"),
        ("/api/alerts/?limit=10&skip=0", "Threat Alerts"),
        ("/api/leaks/?limit=10&skip=0", "Data Leaks"),
        ("/api/questionnaires/?limit=10&skip=0", "Security Questionnaires"),
        ("/api/reports/", "Generated Reports"),
        ("/api/logs/?limit=10&skip=0", "Activity Logs"),
        ("/api/admin/users", "Admin User Management"),
        ("/api/admin/stats", "Admin Monitoring Stats"),
        ("/api/admin/activity-feed", "Admin Activity Feed"),
        ("/api/admin/users/1/export", "GDPR / Compliance Data Export"),
        ("/api/admin/sso/saml", "SAML SSO Stub"),
        ("/api/insider/analyze", "Insider Threat Analysis"),
        ("/api/insider/metrics", "Insider Threat Metrics"),
        ("/api/insider/benchmarks", "ML Model Benchmarks"),
        ("/api/preferences", "User Preferences"),
        ("/api/notifications/webhooks", "Webhook Notifications"),
    ]

    for path, name in endpoints:
        req_ep = urllib.request.Request(f"{base}{path}", headers=headers)
        with urllib.request.urlopen(req_ep) as res:
            assert res.status == 200
            print(f"   [PASS] {name} ({path}): 200 OK")

    print("\n========================================")
    print("SUCCESS: ALL E2E FUNCTIONALITIES VERIFIED 100% OPERATIONAL")
    print("========================================")

if __name__ == "__main__":
    run_tests()
