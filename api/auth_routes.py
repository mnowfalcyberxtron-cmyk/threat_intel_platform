import re
import smtplib
import hashlib
import os
import json
import logging
import asyncio
from datetime import datetime
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from pydantic import BaseModel
from database.db import Database
from config import settings

logger = logging.getLogger("auth")

router = APIRouter(prefix="/api/auth", tags=["Auth"])

_db: Database = None

# Configuration for Admin Email Notifications
ADMIN_EMAIL = "feedsautomate@gmail.com"
ADMIN_PASS = "vblmiceoaklsrklr"

def send_admin_notification(user_name: str, user_email: str):
    """Send an email notification to the admin on new signup."""
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = MIMEMultipart('alternative')
        msg['From'] = ADMIN_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = f"🚨 New User Signup: CyberXTron TIP — {user_name}"

        text_body = f"""New user registered on CyberXTron Threat Intelligence Platform.

Name: {user_name}
Email: {user_email}
Time: {now} IST

Login to the platform to manage this user."""

        html_body = f"""<html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:20px">
<div style="max-width:500px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px">
  <h2 style="color:#00d4ff;margin-top:0">🚨 New User Signup</h2>
  <p style="color:#8b949e;font-size:13px">CyberXTron Threat Intelligence Platform</p>
  <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:16px">
    <tr><td style="padding:8px 0;color:#8b949e;width:80px">Name</td><td style="color:#e6edf3;font-weight:bold">{user_name}</td></tr>
    <tr><td style="padding:8px 0;color:#8b949e">Email</td><td style="color:#e6edf3">{user_email}</td></tr>
    <tr><td style="padding:8px 0;color:#8b949e">Time</td><td style="color:#e6edf3">{now} IST</td></tr>
  </table>
  <p style="margin-top:20px;font-size:11px;color:#8b949e">Login to the admin panel to manage this user's access.</p>
</div>
</body></html>"""

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        server.set_debuglevel(0)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(ADMIN_EMAIL, ADMIN_PASS)
        server.send_message(msg)
        server.quit()
        logger.info(f"Admin notification email sent for new user: {user_email}")
    except Exception as e:
        logger.error(f"Failed to send admin email: {e}")

def hash_password(password: str) -> str:
    """Simple SHA256 hash for passwords with a static salt (for demo/simplicity)."""
    salt = "CyberXTron_Secret_Salt_2026!"
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def validate_password(password: str) -> bool:
    """Must be at least 8 chars and contain at least one special character."""
    if len(password) < 8:
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

@router.post("/signup")
async def signup(req: SignupRequest, request: Request, background_tasks: BackgroundTasks):
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    
    if not validate_password(req.password):
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long and contain a special character.")
    
    existing = await db.get_user_by_email(req.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    # Auto-assign admin role to the specific email
    role = "admin" if req.email.lower() == ADMIN_EMAIL.lower() else "user"
    
    pw_hash = hash_password(req.password)
    user_id = await db.create_user(req.name, req.email, pw_hash, role)
    
    # Log activity
    await db.log_user_activity(user_id, "SIGNUP", f"New account created for {req.email}", request.client.host)

    # Send email notification via BackgroundTasks (properly runs after response)
    background_tasks.add_task(send_admin_notification, req.name, req.email)
    
    return {"message": "Signup successful", "user_id": user_id, "role": role}

@router.post("/login")
async def login(req: LoginRequest, request: Request):
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    user = await db.get_user_by_email(req.email)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    
    pw_hash = hash_password(req.password)
    if user["password"] != pw_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    
    # Log activity
    await db.log_user_activity(user['id'], "LOGIN", f"User logged in from {request.client.host}", request.client.host)

    # Normally we'd return a JWT here. For simplicity, we return user info
    # The frontend will store this in localStorage
    return {
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }

@router.get("/admin/users")
async def get_all_users(email: str, request: Request):
    """Admin-only route to view all users."""
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    user = await db.get_user_by_email(email)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    users = await db.get_all_users()
    return users

@router.delete("/admin/users/{user_id}")
async def delete_user(user_id: int, email: str, request: Request):
    """Admin-only: permanently delete a user by ID."""
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    requester = await db.get_user_by_email(email)
    if not requester or requester["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    # Prevent admin from deleting themselves
    if requester["id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account.")
    
    deleted = await db.delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    
    # Log activity
    await db.log_user_activity(requester["id"], "ADMIN_DELETE_USER", f"Admin deleted user ID {user_id}", request.client.host)
    
    logger.info(f"Admin {email} deleted user ID {user_id}")
    return {"message": "User deleted successfully."}

@router.get("/admin/users/{user_id}/activity")
async def get_user_activity(user_id: int, email: str, request: Request):
    """Admin-only: fetch recent activity for a specific user."""
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    requester = await db.get_user_by_email(email)
    if not requester or requester["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    
    activity = await db.get_user_activity(user_id)
    return activity

@router.get("/health/api-keys")
async def check_api_health(request: Request):
    """Checks the health of currently configured API keys (from X-API-Keys or .env fallback)."""
    results = {}
    timeout = httpx.Timeout(5.0)

    async def check_groq():
        key = settings.GROQ_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {key}"})
                return {"status": "OK" if res.status_code == 200 else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    async def check_openrouter():
        key = settings.OPENROUTER_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.get("https://openrouter.ai/api/v1/auth/key", headers={"Authorization": f"Bearer {key}"})
                return {"status": "OK" if res.status_code == 200 else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    async def check_anthropic():
        key = settings.ANTHROPIC_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.get("https://api.anthropic.com/v1/models", headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
                # Anthropic might return 400 for bad requests, but 401 for bad keys
                return {"status": "OK" if res.status_code in [200, 400] else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    async def check_ollama():
        url = settings.OLLAMA_BASE_URL
        if not url: return {"status": "SKIPPED", "detail": "No URL provided"}
        headers = {}
        if settings.OLLAMA_API_KEY: headers["Authorization"] = f"Bearer {settings.OLLAMA_API_KEY}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.get(f"{url}/api/tags", headers=headers)
                return {"status": "OK" if res.status_code == 200 else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    async def check_ransomware_live():
        key = settings.RANSOMWARE_LIVE_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.get("https://api.ransomware.live/v2/groups", headers={"API_KEY": key})
                return {"status": "OK" if res.status_code == 200 else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}
        
    async def check_hibr():
        key = settings.HIBR_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.get("https://api.haveibeenransom.com/v1/status", headers={"Authorization": f"Bearer {key}"})
                return {"status": "OK" if res.status_code in [200, 403] else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    async def check_abuseipdb():
        key = settings.ABUSEIPDB_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.get("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", headers={"Key": key, "Accept": "application/json"})
                return {"status": "OK" if res.status_code == 200 else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    async def check_threatfox():
        key = settings.THREATFOX_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 1}, headers={"API-KEY": key})
                return {"status": "OK" if res.status_code == 200 else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    async def check_malwarebazaar():
        key = settings.MALWAREBAZAAR_API_KEY
        if not key: return {"status": "SKIPPED", "detail": "No key provided"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                res = await client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": "7de2c1bf58bce09eece701460f17f422"}, headers={"API-KEY": key})
                return {"status": "OK" if res.status_code == 200 else "ERROR", "detail": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "ERROR", "detail": str(e)}

    results["Groq (Primary AI)"] = await check_groq()
    results["OpenRouter (AI)"] = await check_openrouter()
    results["Anthropic (AI)"] = await check_anthropic()
    results["Ollama (Local AI)"] = await check_ollama()
    results["Ransomware.live"] = await check_ransomware_live()
    results["HaveIBeenRansom"] = await check_hibr()
    results["AbuseIPDB"] = await check_abuseipdb()
    results["ThreatFox"] = await check_threatfox()
    results["MalwareBazaar"] = await check_malwarebazaar()

    return results
