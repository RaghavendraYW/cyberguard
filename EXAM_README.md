# CyberGuard v2 — Exam Documentation

## 🌐 URLs for Demo
* **Your Local Dashboard (Admin):** `http://127.0.0.1:8000` or `http://localhost:8000`
* **Coworker/Examiner View (Network IP):** `http://10.114.232.132:8000` 
*(Note: If the network IP above does not load for your examiner, you can find the updated local IP by using the Command Prompt and typing `ipconfig`. Look for the "IPv4 Address" under your main Wi-Fi or Ethernet adapter.)*

## 🔑 Login Credentials

The project database automatically creates these accounts when you start it up. 
You can use them to test the different "Roles":

### 1. The Administrator (Full Access)
Use this to show the complete platform, including the full **Insider Threat Detection** modules, Security Scoring, and **User Monitoring** panels.
* **Email:** `admin@company.com`
* **Password:** `password`

### 2. Standard Coworker (Limited Access)
Use this to demonstrate security. This user is a "Security Analyst" and does NOT have access to the Admin / User Monitoring tab.
* **Email:** `priya@company.com`
* **Password:** `password123`

### 3. Compromised User Demo
Use this account to show an account with a high Risk Level or anomalies.
* **Email:** `rahul@company.com`
* **Password:** `password123`

---

## 🛠️ How to Start the Server (For the Exam)
If you need to reboot or transfer this folder to another PC:
1. Open a terminal or Command Prompt inside the `backend` folder.
2. Run the command: `python main.py`
3. The platform will boot up and re-initialize the `cyberguard.db` automatically if it is missing.
