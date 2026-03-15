#!/bin/bash
echo "🛡 CyberGuard v2.0"
cd "$(dirname "$0")/backend"
pip3 install fastapi uvicorn sqlalchemy "python-jose[cryptography]" werkzeug python-multipart "scikit-learn>=1.6.0" numpy -q
python3 main.py
