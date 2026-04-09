"""
CyberGuard v2.0 — Endpoint Monitoring Agent
Runs on a coworker's machine to transmit active windows/websites to the server.
"""
import os
import sys
import time
import requests
import pygetwindow as gw

API_BASE_URL = "http://10.114.232.132:8000/api/monitoring"
POLL_INTERVAL_SEC = 5

def get_active_window_title():
    try:
        active_window = gw.getActiveWindow()
        if active_window is not None:
            return active_window.title or "Unknown"
    except Exception as e:
        return f"Error: {e}"
    return "Unknown / Desktop"

def main():
    print("="*50)
    print("  CyberGuard Endpoint Agent")
    print("="*50)
    
    tracking_key = sys.argv[1] if len(sys.argv) > 1 else input("Enter your CyberGuard Tracking Key: ").strip()
    if not tracking_key:
        print("Tracking key is required. Exiting.")
        sys.exit(1)
        
    print(f"Connecting to {API_BASE_URL}...")
    
    last_title = None
    
    while True:
        try:
            current_title = get_active_window_title()
            
            # Send telemetry to central server
            payload = {
                "tracking_key": tracking_key,
                "active_window": current_title,
                "status": "active"
            }
            
            resp = requests.post(f"{API_BASE_URL}/ingest", json=payload, timeout=5)
            
            if resp.status_code == 401:
                print("Error: Invalid tracking key.")
                break
            elif resp.status_code != 200:
                print(f"Warning: Server returned {resp.status_code}")
            
            # Log changes to the local console simply for visual tracking
            if current_title != last_title:
                print(f"[{time.strftime('%H:%M:%S')}] Active: {current_title}")
                last_title = current_title

        except requests.exceptions.RequestException as e:
            print(f"[{time.strftime('%H:%M:%S')}] Connection issue: {e}")
            
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Unexpected Error: {e}")
            
        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()
