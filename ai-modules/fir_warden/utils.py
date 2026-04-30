"""
utils.py
Shared utility functions used across all modules.
"""

import hashlib
import uuid
from datetime import datetime

from fastapi import Request


def sha256(text: str) -> str:
    """Return SHA-256 hex digest of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.utcnow().isoformat() + "Z"


def new_id(prefix: str = "") -> str:
    """Generate a short random ID, optionally prefixed."""
    short = str(uuid.uuid4())[:8].upper()
    return f"{prefix}-{short}" if prefix else short


def get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For."""
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_public_ip() -> str:
    """Fetch public IP when on localhost (fallback)."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get("https://api.ipify.org?format=json")
            return resp.json().get("ip", "127.0.0.1")
    except Exception:
        return "127.0.0.1"


async def get_geo_location(ip: str) -> dict:
    """Fetch geo info from IP-API."""
    import httpx
    if not ip or ip in ("127.0.0.1", "localhost", "::1", "unknown"):
        ip = await get_public_ip()

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}")
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                    "isp": data.get("isp", "Unknown"),
                    "risk_level": "LOW" # Basic logic
                }
    except Exception:
        pass
    
    return {
        "ip": ip, "city": "Unknown", "country": "Unknown",
        "lat": 0, "lon": 0, "isp": "Unknown", "risk_level": "LOW"
    }


def diff_dicts(old: dict, new: dict) -> list:
    """
    Return a list of changed fields between two dicts.
    Each entry: {"field": str, "old": value, "new": value}
    """
    changes = []
    for field in set(list(old.keys()) + list(new.keys())):
        o, n = old.get(field, ""), new.get(field, "")
        if o != n:
            changes.append({"field": field, "old": o, "new": n})
    return changes
