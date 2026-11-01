# 🛡️ CyberGuard Zero-Trust Network & WireGuard VPN Architecture

This guide details how to lock down CyberGuard behind a private **Zero-Trust WireGuard VPN** so the application dashboard and backend APIs are inaccessible from the public internet and strictly reserved for authenticated VPN tunnel peers.

---

## 1. Network Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │        Public Internet (WAN)           │
                      └──────────────────┬─────────────────────┘
                                         │
                   Blocked by Firewall   ▼   Allowed on UDP 51820 Only
              [ HTTP / 8000 ]                    [ WireGuard Gateway ]
                     ❌                                   ✅
                                         │
                      ┌──────────────────▼─────────────────────┐
                      │      CyberGuard Host / Gateway         │
                      │   Interface: wg0 (Subnet: 10.8.0.0/24) │
                      │   Gateway IP: 10.8.0.1                 │
                      │                                        │
                      │   Uvicorn Backend Bound To:            │
                      │   10.8.0.1:8000 or 127.0.0.1:8000     │
                      └──────────────────┬─────────────────────┘
                                         │
        ┌────────────────────────────────┴────────────────────────────────┐
        │                 Encrypted ChaCha20-Poly1305 Tunnels             │
        ▼                                                                 ▼
[ Workstation / Laptop ]                                       [ Mobile / Field Device ]
IP: 10.8.0.2                                                   IP: 10.8.0.3
Zero-Trust Posture: Compliant                                  Zero-Trust Posture: Compliant
```

---

## 2. Server-Side WireGuard Gateway Setup

### Step A: Install WireGuard on Server (Linux / Ubuntu / Debian)
```bash
sudo apt update && sudo apt install -y wireguard iptables
```

### Step B: Generate Server Keys
```bash
cd /etc/wireguard
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
```

### Step C: Configure `/etc/wireguard/wg0.conf`
```ini
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <CONTENTS_OF_server_private.key>
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Peer 1: Alex Kumar (Admin)
[Peer]
PublicKey = <CLIENT_1_PUBLIC_KEY>
AllowedIPs = 10.8.0.2/32

# Peer 2: Priya Sharma (Analyst)
[Peer]
PublicKey = <CLIENT_2_PUBLIC_KEY>
AllowedIPs = 10.8.0.3/32
```

### Step D: Enable Packet Forwarding & Start Gateway
```bash
# Enable IPv4 forwarding
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Start & enable WireGuard service
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

---

## 3. Lock Down CyberGuard Access to VPN Only

In production, bind the CyberGuard server to the WireGuard tunnel interface `10.8.0.1` so anyone attempting to connect from the public internet gets connection refused:

### In `.env`:
```ini
HOST=10.8.0.1
PORT=8000
ALLOWED_ORIGINS=http://10.8.0.1:8000
```

### With UFW Firewall:
```bash
# Allow SSH and WireGuard UDP port from outside
sudo ufw allow 22/tcp
sudo ufw allow 51820/udp

# Deny direct public access to port 8000
sudo ufw deny 8000

# Allow traffic to 8000 only over the wg0 interface
sudo ufw allow in on wg0 to any port 8000 proto tcp
sudo ufw enable
```

---

## 4. Connecting Client Devices

1. Open the CyberGuard Dashboard and navigate to the **Perimeter & Network ➔ VPN & Zero-Trust** tab.
2. Locate the employee workstation row or click **+ Provision Client**.
3. Click **⚙️ Conf** to view and download the `.conf` configuration file.
4. Download the official WireGuard client:
   - **Windows / macOS**: [wireguard.com/install](https://www.wireguard.com/install/)
   - **iOS / Android**: Search "WireGuard" in App Store / Google Play.
5. In the WireGuard app, select **Import Tunnel from File** and choose your `.conf` file.
6. Click **Activate**. Once connected, open `http://10.8.0.1:8000` in your browser.

---

## 5. Zero-Trust Killswitch Policy

CyberGuard monitors tunnel telemetry and posture status:
- If a client's tunnel drops, the WireGuard killswitch blocks unencrypted leak traffic (`AllowedIPs = 0.0.0.0/0` with Block untunneled traffic enabled).
- If an employee device fails posture checks (e.g. unapproved device or anomalous subnet), SOC administrators can click **Quarantine** in the CyberGuard dashboard to instantly drop the tunnel.
