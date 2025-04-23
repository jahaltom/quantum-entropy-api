from fastapi import FastAPI, HTTPException, Request, Depends, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from fastapi.security.api_key import APIKeyHeader
import secrets
import hashlib
import os
import datetime
import requests
import sqlite3
import stripe
import smtplib
from email.message import EmailMessage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from collections import defaultdict
import time as time_module

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Rate limiting per IP
RATE_LIMIT = 60
RATE_WINDOW = 60
ip_access_log = defaultdict(list)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        ip = request.client.host
        now = time_module.time()
        ip_access_log[ip] = [t for t in ip_access_log[ip] if now - t < RATE_WINDOW]
        if len(ip_access_log[ip]) >= RATE_LIMIT:
            return HTMLResponse("<h2>Too many requests. Try again later.</h2>", status_code=429)
        ip_access_log[ip].append(now)
        response = await call_next(request)
        return response

app.add_middleware(RateLimitMiddleware)

# Directory to store entropy files
ENTROPY_DIR = "entropy_files"
os.makedirs(ENTROPY_DIR, exist_ok=True)

# Stripe setup
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
YOUR_DOMAIN = "http://localhost:8000"

# Email setup
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

# SQLite setup
DB_PATH = "usage_log.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT,
    tier TEXT,
    size_kb INTEGER,
    filename TEXT,
    timestamp TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS api_keys (
    api_key TEXT PRIMARY KEY,
    tier TEXT,
    created_at TEXT,
    email TEXT
)
""")
conn.commit()

TIER_QUOTAS = {
    "Free Tier": 1024,
    "Pro Tier": 10240,
    "Enterprise Tier": 102400
}

API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

class EntropyRequest(BaseModel):
    size_kb: int

# --- Helper: Send Email --- #
def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

# --- Fetch QRNG seed --- #
def get_qrng_seed():
    url = "https://qrng.anu.edu.au/API/jsonI.php?length=8&type=uint8"
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    data = response.json()
    return bytes(data["data"])

# --- Expand using ChaCha20 --- #
def expand_entropy(seed: bytes, length_bytes: int) -> bytes:
    key = hashlib.sha256(seed).digest()
    nonce = secrets.token_bytes(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(b"\x00" * length_bytes)

# --- Authenticate API key --- #
def authenticate(api_key: str = Depends(API_KEY_HEADER)):
    cursor.execute("SELECT tier FROM api_keys WHERE api_key = ?", (api_key,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")
    return api_key

# --- Check quota --- #
def check_quota(api_key: str, size_kb: int):
    cursor.execute("SELECT tier FROM api_keys WHERE api_key = ?", (api_key,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    tier = row[0]
    quota_kb = TIER_QUOTAS[tier]
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    cursor.execute("SELECT SUM(size_kb) FROM usage_log WHERE api_key = ? AND DATE(timestamp) = ?", (api_key, today))
    total_today = cursor.fetchone()[0] or 0
    if total_today + size_kb > quota_kb:
        raise HTTPException(status_code=429, detail=f"Daily quota exceeded ({total_today + size_kb} / {quota_kb} KB)")

@app.post("/generate_entropy")
def generate_entropy(req: EntropyRequest, api_key: str = Depends(authenticate)):
    if not (1 <= req.size_kb <= 10240):
        raise HTTPException(status_code=400, detail="Size must be between 1KB and 10MB")
    check_quota(api_key, req.size_kb)
    try:
        seed = get_qrng_seed()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"QRNG fetch failed: {str(e)}")
    entropy = expand_entropy(seed, req.size_kb * 1024)
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"entropy_{timestamp}_{req.size_kb}KB.bin"
    path = os.path.join(ENTROPY_DIR, filename)
    with open(path, "wb") as f:
        f.write(entropy)
    cursor.execute("SELECT tier FROM api_keys WHERE api_key = ?", (api_key,))
    tier = cursor.fetchone()[0]
    cursor.execute("INSERT INTO usage_log (api_key, tier, size_kb, filename, timestamp) VALUES (?, ?, ?, ?, ?)", (api_key, tier, req.size_kb, filename, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    return {"file": filename, "bytes": len(entropy), "seed_source": "ANU", "timestamp": timestamp, "tier": tier}

@app.get("/download_entropy/{filename}")
def download_entropy(filename: str, api_key: str = Depends(authenticate)):
    path = os.path.join(ENTROPY_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, media_type='application/octet-stream', filename=filename)

@app.get("/subscribe", response_class=HTMLResponse)
def subscribe_form():
    return HTMLResponse("""
    <html><body>
    <h2>Subscribe for an API Key</h2>
    <form action="/subscribe" method="post">
      <label>Email:<br><input type="email" name="email" required></label><br><br>
      <label>Tier:<br>
        <select name="tier">
          <option value="Free Tier">Free Tier</option>
          <option value="Pro Tier">Pro Tier</option>
          <option value="Enterprise Tier">Enterprise Tier</option>
        </select>
      </label><br><br>
      <button type="submit">Subscribe</button>
    </form>
    </body></html>
    """)

@app.post("/subscribe")
def subscribe_user(tier: str = Form(...), email: str = Form(...)):
    if tier not in TIER_QUOTAS:
        raise HTTPException(status_code=400, detail="Invalid tier")
    api_key = secrets.token_hex(16)
    cursor.execute("INSERT INTO api_keys (api_key, tier, created_at, email) VALUES (?, ?, ?, ?)",
                   (api_key, tier, datetime.datetime.utcnow().isoformat(), email))
    conn.commit()
    send_email(email, f"Your {tier} API Key", f"Thank you for subscribing! Your API Key: {api_key}")
    return HTMLResponse(f"<h3>API Key sent to {email}</h3>")

@app.get("/admin/usage", response_class=HTMLResponse)
def view_usage():
    cursor.execute("SELECT api_key, tier, size_kb, filename, timestamp FROM usage_log ORDER BY timestamp DESC LIMIT 100")
    logs = cursor.fetchall()
    rows = "".join(f"<tr><td>{key}</td><td>{tier}</td><td>{size}</td><td>{fname}</td><td>{ts}</td></tr>" for key, tier, size, fname, ts in logs)
    html = f"""
    <html><head><title>Usage Log</title></head>
    <body>
        <h2>Entropy API Usage Log</h2>
        <table border='1'>
            <tr><th>API Key</th><th>Tier</th><th>Size (KB)</th><th>Filename</th><th>Timestamp</th></tr>
            {rows}
        </table>
    </body></html>
    """
    return html

@app.get("/")
def root():
    return {
        "message": "Quantum Entropy API is live!",
        "usage": "Use /generate_entropy with header X-API-Key to request entropy blocks.",
        "download": "Use /download_entropy/{filename} to retrieve files.",
        "subscribe": "Visit /subscribe to request your API key.",
        "admin": "Visit /admin/usage to view usage logs.",
        "note": "Daily quotas are enforced per API key tier."
    }
