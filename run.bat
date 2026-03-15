@echo off
echo.
echo  =============================================
echo   CyberGuard v2.0  ^|  Production Ready
echo  =============================================
cd /d "%~dp0backend"

echo  [1/3] Installing packages...
pip install -r ../requirements.txt -q

echo  [2/3] Checking .env...
if not exist .env (
    echo  .env not found - copying from example...
    copy ..\.env.example .env
)

echo  [3/3] Starting server...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (set IP=%%a & goto :found)
:found
set IP=%IP: =%

echo.
echo  =============================================
echo   YOUR URL:    http://127.0.0.1:8000
echo   COWORKERS:   http://%IP%:8000
echo.
echo   ADMIN:  admin@company.com  /  password
echo   STAFF:  priya@company.com  /  password123
echo           rahul@company.com  /  password123
echo           sara@company.com   /  password123
echo           james@company.com  /  password123
echo.
echo   Press Ctrl+C to stop
echo  =============================================
echo.
python main.py
pause
