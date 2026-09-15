# core/auth.py
import requests

# Put your Firebase Web API Key here
# Firebase -> Project Settings -> General -> Web API Key
FIREBASE_WEB_API_KEY = "YOUR_ACTUAL_FIREBASE_API_KEY_HERE"
DEMO_LOGIN_ID = "Hacker"
DEMO_PASSWORD = "Kali"

# Authorized Examiners
AUTHORIZED_ADMINS = [
    "admin@ntro.gov.in",
    "examiner@aegisforensics.local",
    "himanshu@admin.local"
]

def verify_examiner_gateway(email, password):
    if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
        return {"success": False, "error": "Email and password are required."}

    if email.casefold() == DEMO_LOGIN_ID.casefold() and password == DEMO_PASSWORD:
        return {"success": True, "email": DEMO_LOGIN_ID, "uid": "LOCAL_DEMO_EXAMINER"}

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    try:
        res = requests.post(url, json=payload, timeout=8)
        data = res.json()
        if res.status_code != 200:
            return {"success": False, "error": data.get("error", {}).get("message", "Authentication Failed")}
        
        user_email = data.get("email", "").lower()
        if user_email not in [a.lower() for a in AUTHORIZED_ADMINS]:
            return {"success": False, "error": "ACCESS DENIED: Account lacks forensic clearance."}
            
        return {"success": True, "email": user_email, "uid": data.get("localId")}
    except Exception:
        # Emergency Fallback for Demo (in case Firebase is not set up yet)
        if "admin" in email.lower() or "ntro" in email.lower():
            return {"success": True, "email": email.lower(), "uid": "LOCAL_DEMO_EXAMINER"}
        return {"success": False, "error": "Connection Error to Authentication Gateway."}