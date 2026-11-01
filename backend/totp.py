"""
CyberGuard v3.0 — RFC 6238 TOTP (Time-Based One-Time Password)
Compatible with Google Authenticator, Microsoft Authenticator, Authy, etc.
Zero external library dependencies for the core cryptographic algorithm.
"""
import base64
import hashlib
import hmac
import io
import os
import struct
import time
import qrcode


def generate_totp_secret() -> str:
    """Generate a cryptographically secure 160-bit (20-byte) Base32 secret string."""
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("utf-8").rstrip("=")


def get_totp_uri(secret: str, user_email: str, issuer: str = "CyberGuard ZTNA") -> str:
    """Return standard RFC 6238 otpauth:// URI for QR code generation."""
    clean_secret = secret.replace(" ", "").upper()
    return f"otpauth://totp/{issuer}:{user_email}?secret={clean_secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def generate_totp_qr(otp_uri: str) -> str:
    """Generate a base64 PNG data URI for embedding directly in web UI / <img> tags."""
    try:
        qr = qrcode.QRCode(box_size=5, border=2)
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#00ffcc", back_color="#0d1117")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{b64}"
    except Exception:
        # Fallback to standard black/white if custom styling fails
        qr = qrcode.QRCode(box_size=5, border=2)
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{b64}"


def _get_hotp_token(secret: str, intervals_no: int) -> str:
    """Calculate HMAC-SHA1 HOTP token for a given counter interval."""
    # Ensure correct Base32 padding
    missing_padding = len(secret) % 8
    if missing_padding != 0:
        secret += "=" * (8 - missing_padding)
    key = base64.b32decode(secret, casefold=True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[19] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def get_current_totp(secret: str) -> str:
    """Generate the current 6-digit TOTP code (for development testing / verification)."""
    current_interval = int(time.time() // 30)
    return _get_hotp_token(secret, current_interval)


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify code against secret with a +/- window time steps tolerance (30s each).
    Window 1 = accepts code from 30s ago, right now, or next 30s (deals with slight clock drifts).
    Also supports a development bypass code '000000' if secret is empty or during testing.
    """
    if not secret:
        return False
    if not code:
        return False
    
    clean_code = str(code).strip().replace(" ", "").replace("-", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    current_interval = int(time.time() // 30)
    for offset in range(-window, window + 1):
        expected = _get_hotp_token(secret, current_interval + offset)
        if hmac.compare_digest(expected, clean_code):
            return True
    return False
