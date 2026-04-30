"""
net_watch.py
Net-Watch module.
Responsibilities:
  - IPinfo.io geo + threat lookup
  - DDoS detection (rolling window counter)
  - Real-time in-memory event store (circular buffer for live map)
  - IP log persistence
  - Unauthorized access event emission
"""

import time
import threading
from collections import deque, defaultdict

import requests

from fir_warden.config   import IPINFO_TOKEN, AUTHORIZED_IPS, DDOS_THRESHOLD, DDOS_WINDOW
from fir_warden.database import emit_event, log_audit, get_supabase
from .fusion             import check_ddos_fusion
from fir_warden.utils    import now_iso

# ── Real-time in-memory buffer (last 500 access events for live map) ─────────
rt_events: deque = deque(maxlen=500)
rt_lock = threading.Lock()

# ── DDoS rolling-window tracker ───────────────────────────────────────────────
_ddos_tracker: dict = defaultdict(list)
_ddos_lock = threading.Lock()


# ── IP Intelligence ───────────────────────────────────────────────────────────

def ipinfo_lookup(ip: str) -> dict:
    """
    Query IPinfo.io lite API for geo + threat data.
    Returns a standard dict. Local IPs return a safe default.
    """
    if ip in ("127.0.0.1", "::1", "testclient", "unknown"):
        return {
            "ip": ip, "city": "Localhost", "region": "Local",
            "country": "IN", "org": "Local Network",
            "lat": 12.97, "lon": 77.59,
            "abuse_score": 0, "is_vpn": False,
            "is_proxy": False, "is_tor": False,
            "threat_level": "NONE",
        }
    try:
        r = requests.get(
            f"https://api.ipinfo.io/lite/{ip}",
            params={"token": IPINFO_TOKEN},
            timeout=5
        )
        d = r.json()
        loc      = d.get("loc", "0,0").split(",")
        privacy  = d.get("privacy", {}) if isinstance(d.get("privacy"), dict) else {}
        abuse_d  = d.get("abuse", {})   if isinstance(d.get("abuse"),   dict) else {}

        is_vpn   = privacy.get("vpn",   False)
        is_proxy = privacy.get("proxy", False)
        is_tor   = privacy.get("tor",   False)
        abuse    = abuse_d.get("score",  0)

        if is_tor or abuse > 80:
            threat_level = "CRITICAL"
        elif is_proxy or abuse > 40:
            threat_level = "HIGH"
        elif is_vpn or abuse > 10:
            threat_level = "MEDIUM"
        else:
            threat_level = "NONE"

        return {
            "ip":           ip,
            "city":         d.get("city",    "Unknown"),
            "region":       d.get("region",  "Unknown"),
            "country":      d.get("country", "Unknown"),
            "org":          d.get("org",     "Unknown"),
            "lat":          float(loc[0]) if len(loc) == 2 else 0,
            "lon":          float(loc[1]) if len(loc) == 2 else 0,
            "abuse_score":  abuse,
            "is_vpn":       is_vpn,
            "is_proxy":     is_proxy,
            "is_tor":       is_tor,
            "threat_level": threat_level,
        }
    except Exception as e:
        return {
            "ip": ip, "city": "Unknown", "region": "Unknown",
            "country": "Unknown", "org": "Unknown",
            "lat": 0, "lon": 0, "abuse_score": 0,
            "is_vpn": False, "is_proxy": False, "is_tor": False,
            "threat_level": "UNKNOWN", "error": str(e),
        }


# ── DDoS Detection ────────────────────────────────────────────────────────────

def ddos_check(ip: str) -> bool:
    """
    Return True if this IP has exceeded DDOS_THRESHOLD requests
    within the last DDOS_WINDOW seconds.
    """
    now_ = time.time()
    with _ddos_lock:
        _ddos_tracker[ip] = [t for t in _ddos_tracker[ip] if now_ - t < DDOS_WINDOW]
        _ddos_tracker[ip].append(now_)
        return len(_ddos_tracker[ip]) > DDOS_THRESHOLD


# ── Real-time Event Store ─────────────────────────────────────────────────────

def push_rt_event(
    ip: str, city: str, country: str, org: str,
    lat: float, lon: float, auth: bool,
    fir_id: str = None, threat: str = "NONE", ddos: bool = False
) -> dict:
    """
    Push a standardised event into the real-time in-memory store.
    This feeds the live map and the 2-second polling endpoint.
    """
    fusion_alert = None
    if not auth and ddos:
        fusion_alert = "HIGH RISK: Unauthorized access + Flooding"
    elif ddos:
        fusion_alert = "DDoS Suspected: High request frequency detected"

    ev = {
        "ip":           ip,
        "lat":          lat,
        "lon":          lon,
        "city":         city,
        "country":      country,
        "org":          org,
        "auth":         auth,
        "fir_id":       fir_id,
        "threat":       "DDoS Suspected" if ddos else threat,
        "fusion_alert": fusion_alert,
        "timestamp":    now_iso(),
    }
    with rt_lock:
        rt_events.appendleft(ev)
    return ev


def get_rt_events() -> list:
    """Return the real-time in-memory event list (newest first)."""
    with rt_lock:
        return list(rt_events)


# ── Core Net-Watch Logic ─────────────────────────────────────────────────────

def process_fir_access(client_ip: str, fir_id: str):
    """
    Called whenever a FIR is accessed.
    Runs geo lookup, DDoS check, logs the access, emits events.
    Returns (is_authorized, geo) for the caller.
    """
    is_authorized = client_ip in AUTHORIZED_IPS
    is_ddos       = ddos_check(client_ip)
    geo           = ipinfo_lookup(client_ip)
    threat_label  = "DDoS Suspected" if is_ddos else geo["threat_level"]

    # Always log every access (auth or not)
    try:
        sb = get_supabase()
        sb.table("ip_log").insert({
            "ip": client_ip,
            "fir_id": fir_id,
            "context": "fir_access",
            "authorized": int(is_authorized),
            "geo": geo,
            "threat": {"level": threat_label},
            "ts": now_iso()
        }).execute()
    except Exception:
        pass

    if not is_authorized:
        try:
            emit_event("UNAUTH_ACCESS", geo.get("city", "Unknown"), 0.85,
                       {"ip": client_ip, "fir_id": fir_id, "threat": geo["threat_level"]})
            log_audit("UNAUTHORIZED_FIR_ACCESS", {"ip": client_ip, "fir_id": fir_id})
        except Exception: pass

    if is_ddos:
        try:
            emit_event("DDOS_SUSPECTED", geo.get("city", "Unknown"), 0.9,
                       {"ip": client_ip, "fir_id": fir_id})
            log_audit("DDOS_SUSPECTED", {"ip": client_ip, "fir_id": fir_id})
            if not is_authorized:
                check_ddos_fusion(client_ip, fir_id)
        except Exception: pass

    # Push to real-time map store
    push_rt_event(
        ip=client_ip,
        city=geo.get("city", "Unknown"),
        country=geo.get("country", "Unknown"),
        org=geo.get("org", "Unknown"),
        lat=geo.get("lat", 0),
        lon=geo.get("lon", 0),
        auth=is_authorized,
        fir_id=fir_id,
        threat=geo["threat_level"],
        ddos=is_ddos,
    )

    return is_authorized, geo


def manual_ip_check(ip: str, context: str) -> dict:
    """
    Manual IP check from the Net-Watch UI.
    Logs the lookup and emits UNAUTH_ACCESS if not in the allowed list.
    """
    geo     = ipinfo_lookup(ip)
    is_auth = ip in AUTHORIZED_IPS
    ts      = now_iso()

    try:
        get_supabase().table("ip_log").insert({
            "ip": ip,
            "fir_id": None,
            "context": context,
            "authorized": int(is_auth),
            "geo": geo,
            "threat": {"level": geo["threat_level"]},
            "ts": ts
        }).execute()
    except Exception: pass

    if not is_auth:
        try:
            emit_event("UNAUTH_ACCESS", geo.get("city", "Unknown"), 0.8,
                       {"ip": ip, "threat_level": geo["threat_level"]})
        except Exception: pass

    return {"ip": ip, "authorized": is_auth, "geo": geo, "ts": ts}


def get_ip_log() -> list:
    """Return the full IP access log (newest first, max 100)."""
    try:
        res = get_supabase().table("ip_log").select("*").order("ts", desc=True).limit(100).execute()
        return res.data if res.data else []
    except Exception:
        return []
