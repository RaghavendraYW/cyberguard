"""
CyberGuard v2.0 — Scan Helpers
SSL, HTTP header, and port scanning functions.
"""
import ssl
import socket
import urllib.request
import ipaddress
from datetime import datetime, timezone

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_safe_target(domain: str) -> bool:
    """Validate that the domain does not resolve to private, loopback, or cloud metadata IP."""
    try:
        ips = socket.getaddrinfo(domain, None)
        for info in ips:
            addr = ipaddress.ip_address(info[4][0])
            for net in _BLOCKED_NETWORKS:
                if addr in net:
                    return False
        return True
    except Exception:
        return False


def ssl_check(domain):
    r = {"grade": "F", "valid": False, "days_left": 0, "findings": []}
    if not is_safe_target(domain):
        r["findings"].append("Target resolves to restricted internal/private IP range (SSRF blocked)")
        return r
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.now(timezone.utc)).days
            r.update({"valid": True, "days_left": days, "expiry": exp.strftime("%Y-%m-%d")})
            r["grade"] = "F" if days <= 0 else "D" if days <= 7 else "C" if days <= 30 else "A"
            if days <= 7:
                r["findings"].append(f"SSL {'EXPIRED' if days <= 0 else f'expiring in {days} days — URGENT'}")
    except Exception as e:
        r["findings"].append(f"SSL check failed: {type(e).__name__}")
    return r


def header_check(domain):
    r = {"grade": "F", "findings": []}
    if not is_safe_target(domain):
        r["findings"].append("Target resolves to restricted internal/private IP range (SSRF blocked)")
        return r
    hdrs = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
    try:
        req = urllib.request.Request(f"https://{domain}", headers={"User-Agent": "CyberGuard/2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            rh = {k.lower() for k in dict(resp.headers)}
            present = sum(1 for h in hdrs if h.lower() in rh)
            for h in hdrs:
                if h.lower() not in rh:
                    r["findings"].append(f"Missing header: {h}")
            pct = present / len(hdrs)
            r["grade"] = "A" if pct >= 0.8 else "B" if pct >= 0.6 else "C" if pct >= 0.4 else "D" if pct >= 0.2 else "F"
    except Exception as e:
        r["findings"].append(f"Header check failed: {type(e).__name__}")
    return r


def port_check(domain):
    r = {"dangerous_ports": [], "findings": []}
    if not is_safe_target(domain):
        r["findings"].append("Target resolves to restricted internal/private IP range (SSRF blocked)")
        return r
    for port, name in [(22, "SSH"), (3389, "RDP"), (23, "Telnet"), (8080, "HTTP-alt")]:
        try:
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex((domain, port)) == 0:
                r["dangerous_ports"].append(port)
                r["findings"].append(f"Port {port} ({name}) exposed to internet")
            s.close()
        except Exception:
            pass
    return r
