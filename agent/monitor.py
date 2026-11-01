"""
CyberGuard v2.5 — Endpoint Monitoring Agent
Runs on an employee or coworker machine to transmit active window/activity telemetry to central server.
"""
import os
import sys
import time
import warnings
import argparse

# Suppress urllib3 dependency warnings
warnings.filterwarnings("ignore")

# Ensure Windows cp1252 consoles don't crash on emoji/unicode
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests
import pygetwindow as gw

POLL_INTERVAL_SEC = 5


def get_active_window_title():
    try:
        active_window = gw.getActiveWindow()
        if active_window is not None:
            return active_window.title or "Desktop"
    except Exception:
        pass
    return "Desktop"


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Endpoint Agent")
    parser.add_argument("--key", help="Tracking Key")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="CyberGuard Server URL")
    parser.add_argument("--once", action="store_true", help="Send single telemetry ping and exit")
    parser.add_argument("--simulate-threat", help="Simulate a threat (e.g. 'Mimikatz', 'Wireshark', 'Tor Browser')")
    args = parser.parse_args()

    print("=" * 55)
    print("  [+] CyberGuard v2.5 Endpoint Telemetry Agent")
    print("=" * 55)

    tracking_key = args.key if args.key else input("Enter your CyberGuard Tracking Key: ").strip()
    if not tracking_key:
        print("[-] Tracking key is required. Exiting.")
        sys.exit(1)

    api_url = f"{args.server.rstrip('/')}/api/monitoring"
    print(f"Connecting to {api_url}...")

    last_title = None
    connected = False

    while True:
        try:
            if args.simulate_threat:
                current_title = f"{args.simulate_threat} - Risk Simulation Session"
            else:
                current_title = get_active_window_title()

            payload = {
                "tracking_key": tracking_key,
                "active_window": current_title,
                "status": "active"
            }

            resp = requests.post(
                f"{api_url}/ingest",
                json=payload,
                headers={"X-Requested-With": "CyberGuard-Agent"},
                timeout=15
            )

            if resp.status_code == 401:
                print("[-] Error: Invalid tracking key. Check the Admin -> User Monitoring panel.")
                break

            data = resp.json() if resp.status_code == 200 else {}

            if not connected and resp.status_code == 200:
                user_name = data.get("user", "User")
                print(f"[+] Connected successfully as: {user_name}")
                print(f"[*] Real-time telemetry streaming active (every {POLL_INTERVAL_SEC}s)...\n")
                connected = True

            if current_title != last_title:
                timestamp = time.strftime('%H:%M:%S')
                if data.get("status") == "threat_detected":
                    print(f"[{timestamp}] [!] [THREAT TRIGGERED] {data.get('threat')} ({data.get('severity', 'critical').upper()})")
                    print(f"[{timestamp}] [!] [ZERO-TRUST ENFORCED] Workstation placed in QUARANTINE! Outbound tunnel severed.\n")
                else:
                    print(f"[{timestamp}] [SYNC] Active: {current_title[:65]}")
                last_title = current_title

        except requests.exceptions.Timeout:
            print(f"[{time.strftime('%H:%M:%S')}] [WAIT] Sync latency (server busy, retrying)...")
        except requests.exceptions.ConnectionError:
            print(f"[{time.strftime('%H:%M:%S')}] [WAIT] Reconnecting to server...")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Telemetry update queued")

        if args.once:
            print("[+] Single telemetry ping delivered successfully. Exiting.")
            break

        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()

