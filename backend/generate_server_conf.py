import os
import sys

sys.path.append(os.path.dirname(__file__))

from database import DBSession, VPNConnectionDB
from routes.vpn import generate_wireguard_keypair

def build_server_config():
    db = DBSession()
    nodes = db.query(VPNConnectionDB).all()
    s_priv = "mkKZkxvOwzlp9BwfdfIPvsQtwDLsywh24UnBWdDnyYo="

    lines = [
        "[Interface]",
        f"PrivateKey = {s_priv}",
        "ListenPort = 51820",
        "Address = 10.8.0.1/24",
        ""
    ]

    for n in nodes:
        c_priv, c_pub = generate_wireguard_keypair(f"cyberguard_client_{n.id}_{n.user_email}")
        lines.append(f"# Peer {n.id}: {n.user_name} - {n.device_name}")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {c_pub}")
        lines.append(f"AllowedIPs = {n.virtual_ip}/32")
        lines.append("")

    content = "\n".join(lines)
    out_path = os.path.join(os.path.dirname(__file__), "cyberguard-gateway.conf")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Generated {out_path} with {len(nodes)} peers")
    return out_path, content

if __name__ == "__main__":
    path, conf = build_server_config()
    print("--- PREVIEW ---")
    print(conf)
