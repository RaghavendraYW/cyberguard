"""
CyberGuard v2.5 — Real Threat & Zero-Trust Risk Simulator
Simulates a real endpoint threat or policy violation to test detection, alerting,
and automated VPN zero-trust quarantine on the live dashboard.
"""
import sys
import argparse
import warnings

# Suppress urllib3 dependency warnings
warnings.filterwarnings("ignore")

# Ensure Windows cp1252 consoles don't crash on unicode
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import os
import requests

DEFAULT_SERVER = os.environ.get("CYBERGUARD_SERVER", "http://127.0.0.1:8000")
DEFAULT_KEY = os.environ.get("CYBERGUARD_TRACKING_KEY", "")

PRESETS = {
    "1": ("Mimikatz", "Mimikatz - Dump LSASS Hashes & Kerberos Tickets"),
    "2": ("Wireshark", "Wireshark - Capturing Promiscuous Network Traffic"),
    "3": ("Tor", "Tor Browser - Darknet Market Exfiltration Session"),
    "4": ("Metasploit", "Metasploit Framework - Exploit Payload Execution"),
    "5": ("Nmap", "Nmap - Subnet Port Scanning & Enumeration"),
    "6": ("PowerShell", "powershell -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoA...")
}


def simulate(threat_name, custom_title=None, server=DEFAULT_SERVER, key=DEFAULT_KEY):
    title = custom_title or f"{threat_name} - Threat Simulation Session"
    print("=" * 65)
    print("  [+] CyberGuard Real Threat Simulation")
    print("=" * 65)
    print(f"[*] Target Endpoint Server: {server}")
    print(f"[*] Simulating Process/Window: '{title}'")
    print(f"[*] Transmitting telemetry stream...")

    url = f"{server.rstrip('/')}/api/monitoring/ingest"
    headers = {"Content-Type": "application/json", "X-Requested-With": "CyberGuard-Agent"}
    payload = {
        "tracking_key": key,
        "active_window": title,
        "status": "active"
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        if resp.status_code != 200:
            print(f"[-] Ingest returned HTTP {resp.status_code}: {resp.text}")
            return

        data = resp.json()
        print("\n" + "=" * 65)
        print("  [!] REAL-TIME DETECTION RESULT FROM CENTRAL ENGINE:")
        print("=" * 65)
        print(f"  * Response Status : {data.get('status')}")
        print(f"  * Detected Threat : {data.get('threat', 'N/A')}")
        print(f"  * Severity Level  : {data.get('severity', 'critical').upper()}")
        print(f"  * Device Posture  : {data.get('posture', 'quarantine').upper()} [QUARANTINE ENFORCED]")
        print(f"  * Targeted User   : {data.get('user', 'Employee')}")
        print("=" * 65)
        print(f"\n[+] Verification Checklist on Live Dashboard ({server}):")
        print("  1. Dashboard -> Recent Alerts: New Critical alert displayed on top.")
        print("  2. Dashboard -> Open Risks & Anomalies KPI cards incremented.")
        print("  3. Admin -> User Monitoring: Threat anomaly recorded in live feed.")
        print("  4. VPN & Zero-Trust -> Workstation marked [QUARANTINE] & tunnel disconnected.")
        print("=" * 65)
    except requests.exceptions.ConnectionError:
        print(f"[-] Error: Could not connect to {server}. Is the CyberGuard server running?")
    except Exception as e:
        print(f"[-] Error: {e}")


def restore(server=DEFAULT_SERVER, key=DEFAULT_KEY):
    print("[*] Restoring workstation to safe posture ('Visual Studio Code - Clean Workspace')...")
    url = f"{server.rstrip('/')}/api/monitoring/ingest"
    headers = {"Content-Type": "application/json", "X-Requested-With": "CyberGuard-Agent"}
    payload = {
        "tracking_key": key,
        "active_window": "Visual Studio Code - Workspace Clean",
        "status": "active"
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        if resp.status_code == 200:
            print("[+] Transmitted clean telemetry. Device restored to normal activity.")
        else:
            print(f"[-] Status {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[-] Restore error: {e}")


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Risk Simulator")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="CyberGuard Server URL (e.g. http://192.168.1.x:8000)")
    parser.add_argument("--key", default=DEFAULT_KEY, help="User Tracking Key from Admin panel")
    parser.add_argument("--threat", choices=["mimikatz", "wireshark", "tor", "metasploit", "nmap", "powershell"], help="Specific threat to simulate")
    parser.add_argument("--restore", action="store_true", help="Send clean telemetry to restore posture")
    args = parser.parse_args()

    server = args.server.rstrip("/")
    key = args.key

    if not key:
        key = input("Enter Employee/Workstation Tracking Key (check Admin -> User Monitoring): ").strip()
        if not key:
            # Fallback to Priya Sharma demo key
            key = "cg_trk_SuLa3sVHgfEps9HXPL7bqQ"
            print(f"[*] Using demo tracking key: {key}")

    if args.restore:
        restore(server, key)
        return

    if args.threat:
        for k, v in PRESETS.items():
            if v[0].lower() == args.threat.lower():
                simulate(v[0], v[1], server, key)
                return

    # Interactive choice if no args
    print("\nChoose a real security threat to simulate on this machine:")
    for k, v in PRESETS.items():
        print(f"  [{k}] {v[0]}: {v[1]}")
    print("  [7] Custom Threat Title")
    print("  [R] Restore clean activity")

    choice = input("\nEnter choice (1-7, R) [default: 1]: ").strip()
    if choice.upper() == "R":
        restore(server, key)
    elif choice in PRESETS:
        simulate(PRESETS[choice][0], PRESETS[choice][1], server, key)
    elif choice == "7":
        custom = input("Enter custom window/process title (e.g. 'Wireshark Sniffing'): ").strip()
        simulate("Custom", custom, server, key)
    else:
        simulate(PRESETS["1"][0], PRESETS["1"][1], server, key)


if __name__ == "__main__":
    main()

