# ══════════════════════════════════════════════════════════════════════════════
# KAVACH FIR-Warden Main Module (Unified Architecture)
# ══════════════════════════════════════════════════════════════════════════════

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request, Response, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fir_warden")

# ── Lifespan (Startup/Shutdown) ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize local DB on startup
    from .database import init_db
    init_db()
    logger.info("FIR-Warden: Local SQLite initialized.")
    yield
    logger.info("FIR-Warden: Shutting down.")

app = FastAPI(
    title="KAVACH FIR-Warden",
    description="Primary FIR management and unified backend gateway",
    version="2.1.0",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Unified App Imports & Mounting ───────────────────────────────────────────
from crowd_sentinel.main import app as sentinel_app
from deep_trace.main import app as deeptrace_app

# This allows the entire system to run in ONE process on ONE port (e.g. 7860)
app.mount("/api/proxy/sentinel", sentinel_app)
app.mount("/api/proxy/deeptrace", deeptrace_app)

# ── cross-module imports ─────────────────────────────────────────────────────
from net_watch.net_watch import process_fir_access, manual_ip_check, get_ip_log, get_rt_events
from doc_guard.doc_guard import upload_document, verify_document, list_documents
from .fraud_scorer import compute_fraud_score, get_account_risk_signal
from net_watch.fusion import check_transaction_fraud

# ── Pydantic models ──────────────────────────────────────────────────────────
class FIRCreate(BaseModel):
    # Frontend fields (fir.html form)
    fir_number:        Optional[str] = None       # e.g. FIR-2026-9001
    complainant:       Optional[str] = None       # complainant full name
    incident_type:     Optional[str] = "GENERAL"  # category / dropdown
    date_of_incident:  Optional[str] = None       # YYYY-MM-DD
    location:          str                        # city / branch / ATM ID
    officer_id:        Optional[str] = None       # officer badge ID
    description:       str                        # full incident description
    priority:          str = "MEDIUM"             # LOW / MEDIUM / HIGH
    # Legacy / optional extra fields
    title:             Optional[str] = None
    contact:           Optional[str] = None
    category:          Optional[str] = None
    metadata:          Optional[dict] = None

class TransactionCreate(BaseModel):
    account_id: str
    amount: float
    channel: str = "MOBILE_APP"
    ip_address: Optional[str] = None
    net_watch_signal: float = 0.0
    doc_guard_signal: float = 0.0
    deep_trace_signal: float = 0.0
    sentinel_signal: float = 0.0

# ── Utils ────────────────────────────────────────────────────────────────────
def get_client_ip(request: Request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded: return forwarded.split(",")[0]
    return request.client.host if request.client else "127.0.0.1"

# ── FIR APIs ─────────────────────────────────────────────────────────────────
@app.post("/api/fir/report")
async def api_create_fir(body: FIRCreate, request: Request):
    from .database import get_supabase, emit_event
    from .utils import now_iso
    import uuid, hashlib, json
    
    fir_id = "FIR-" + str(uuid.uuid4())[:8].upper()
    ts = now_iso()
    ip = get_client_ip(request)
    
    # Normalise fields — accept both frontend form fields and legacy fields
    complainant   = body.complainant or body.contact or "Unknown"
    incident_type = body.incident_type or body.category or "GENERAL"
    title         = body.title or f"{incident_type} - {complainant}"
    location      = body.location or "Unknown"
    
    # Generate SHA-256 integrity hash of the FIR content
    fir_content = json.dumps({
        "fir_id":         fir_id,
        "fir_number":     body.fir_number or fir_id,
        "complainant":    complainant,
        "incident_type":  incident_type,
        "date":           body.date_of_incident or ts[:10],
        "location":       location,
        "officer_id":     body.officer_id or "—",
        "description":    body.description,
        "created_at":     ts,
    }, sort_keys=True)
    fir_hash = hashlib.sha256(fir_content.encode()).hexdigest()
    
    # DB record — mapped to actual SQLite schema columns
    fir_record = {
        "id":                fir_id,
        "fir_number":        body.fir_number or fir_id,
        "complainant_name":  complainant,
        "category":          incident_type,
        "incident_date":     body.date_of_incident or ts[:10],
        "incident_location": location,
        "filed_by":          body.officer_id or "ADMIN",
        "description":       body.description,
        "priority":          body.priority or "MEDIUM",
        "severity":          body.priority or "MEDIUM",
        "status":            "PENDING",
        "blockchain_hash":   fir_hash,
        "created_at":        ts,
    }
    
    try:
        get_supabase().table("firs").insert(fir_record).execute()
    except Exception as e:
        logger.error(f"FIR insert error: {e}")
        raise HTTPException(status_code=500, detail=f"DB error: {e}")
    
    emit_event("FIR_REPORTED", location, 0.5, fir_record)
    process_fir_access(fir_id, ip)
    
    return {
        "status":     "success",
        "fir_id":     fir_id,
        "fir_hash":   fir_hash,
        "created_at": ts,
        "message":    f"FIR {fir_id} registered and hash anchored."
    }

@app.get("/api/fir")
async def api_list_firs():
    from .database import get_supabase
    rows = get_supabase().table("firs").select("*").order("created_at", desc=True).execute().data
    # Normalize column names for frontend compatibility
    result = []
    for r in rows:
        result.append({
            "fir_id":           r.get("id") or r.get("fir_id"),
            "fir_number":       r.get("fir_number"),
            "complainant":      r.get("complainant_name") or r.get("complainant") or r.get("contact"),
            "incident_type":    r.get("category") or r.get("incident_type") or "—",
            "date_of_incident": r.get("incident_date") or r.get("date_of_incident") or r.get("created_at", "")[:10],
            "location":         r.get("incident_location") or r.get("location") or "—",
            "officer_id":       r.get("filed_by") or r.get("officer_id") or "—",
            "description":      r.get("description") or "—",
            "priority":         r.get("priority") or "MEDIUM",
            "status":           r.get("status") or "PENDING",
            "workflow_status":  r.get("workflow_status") or "PENDING",
            "rejection_reason": r.get("rejection_reason"),
            "reviewed_by":      r.get("reviewed_by_name"),
            "reviewed_at":      r.get("reviewed_at"),
            "image_url":        r.get("image_url"),
            "fir_hash":         r.get("blockchain_hash") or r.get("fir_hash") or r.get("hash"),
            "created_at":       r.get("created_at"),
            "tampered":         False,
        })
    return result

# ── Police HQ APIs ───────────────────────────────────────────────────────────
@app.get("/api/police/stats")
async def api_police_stats():
    from .database import get_supabase
    sb = get_supabase()
    try:
        firs = sb.table("firs").select("workflow_status, priority").execute().data or []
        detections = sb.table("sentinel_detections").select("id").execute().data or []
        
        pending  = len([f for f in firs if f.get("workflow_status") == "PENDING"])
        verified = len([f for f in firs if f.get("workflow_status") == "VERIFIED"])
        rejected = len([f for f in firs if f.get("workflow_status") == "REJECTED"])
        high_pri = len([f for f in firs if f.get("priority") == "HIGH"])
        
        return {
            "pending_firs":  pending,
            "verified_firs": verified,
            "rejected_firs": rejected,
            "high_priority": high_pri,
            "total_detections": len(detections),
            "hq_status": "OPERATIONAL" if pending < 10 else "BUSY"
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/police/detections")
async def api_list_detections():
    from .database import get_supabase
    try:
        rows = get_supabase().table("sentinel_detections").select("*").order("created_at", desc=True).limit(50).execute().data
        return rows
    except Exception: return []

@app.post("/api/police/detections")
async def api_log_detection(body: dict):
    from .database import get_supabase
    try:
        get_supabase().table("sentinel_detections").insert({
            "detection_type": body.get("type"),
            "confidence":     body.get("confidence", 0.0),
            "location":       body.get("location", "UNKNOWN"),
            "image_path":     body.get("image_path"),
            "metadata_json":  body.get("metadata", {}),
            "risk_level":     body.get("risk_level", "LOW")
        }).execute()
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

class PoliceAction(BaseModel):
    fir_id: str
    status: str # VERIFIED, REJECTED, UNDER_REVIEW
    officer: str
    reason: Optional[str] = None

@app.post("/api/police/verify")
async def api_police_verify(body: PoliceAction):
    from .database import get_supabase, log_audit
    from .utils import now_iso
    sb = get_supabase()
    
    # Get current status for audit
    current = sb.table("firs").select("workflow_status").eq("id", body.fir_id).execute().data
    prev_status = current[0].get("workflow_status") if current else "UNKNOWN"
    
    ts = now_iso()
    try:
        # Update FIR
        sb.table("firs").update({
            "workflow_status": body.status,
            "rejection_reason": body.reason if body.status == "REJECTED" else None,
            "reviewed_by_name": body.officer,
            "reviewed_at": ts,
            "status": "closed" if body.status in ("VERIFIED", "REJECTED") else "open"
        }).eq("id", body.fir_id).execute()
        
        # Log to dedicated FIR audit table
        sb.table("fir_audit").insert({
            "fir_id": body.fir_id,
            "action": f"STATUS_UPDATE_{body.status}",
            "previous_status": prev_status,
            "new_status": body.status,
            "performed_by": body.officer,
            "reason": body.reason or "Standard review"
        }).execute()
        
        return {"status": "success", "message": f"FIR {body.fir_id} updated to {body.status}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/police/audit/{fir_id}")
async def api_get_fir_audit(fir_id: str):
    from .database import get_supabase
    try:
        rows = get_supabase().table("fir_audit").select("*").eq("fir_id", fir_id).order("timestamp", desc=True).execute().data
        return rows
    except Exception: return []

# ── Event APIs ───────────────────────────────────────────────────────────────
@app.post("/api/event")
async def api_log_event(body: dict):
    from .database import emit_event
    try:
        emit_event(
            body.get("event_type", "UNKNOWN"),
            body.get("location", "UNKNOWN"),
            body.get("confidence", 0.0),
            body.get("payload", {})
        )
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Event Log Error: {e}")
        return {"status": "error", "message": str(e)}

# ── Net Watch APIs ───────────────────────────────────────────────────────────
@app.get("/api/net-watch/access-log")
async def api_get_access_log():
    from .database import get_supabase
    sb = get_supabase()
    try:
        rows = sb.table("ip_log").select("*").order("logged_at", desc=True).limit(50).execute().data
        result = []
        for r in rows:
            geo = r.get("geo") or {}
            threat = geo.get("threat_level", "LOW")
            anomalies = []
            if geo.get("is_tor"): anomalies.append("TOR Exit Node")
            if geo.get("is_vpn"): anomalies.append("VPN Detected")
            if geo.get("is_proxy"): anomalies.append("Proxy Server")
            if threat in ("HIGH","CRITICAL"): anomalies.append("High Threat IP")
            if r.get("flagged"): anomalies.append("Flagged")

            result.append({
                "ip": r.get("ip_address") or r.get("ip", "—"),
                "location": f"{r.get('city') or geo.get('city','?')}, {r.get('country') or geo.get('country','?')}",
                "city": r.get("city") or geo.get("city", "Unknown"),
                "country": r.get("country") or geo.get("country", "Unknown"),
                "isp": geo.get("isp", "Unknown Provider"),
                "time": (r.get("logged_at","")[:19] or "").replace("T"," "),
                "anomalies": anomalies,
                "attempts": r.get("count", 1),
                "status": "BLOCKED" if r.get("flagged") else "REVIEW" if threat in ("HIGH","CRITICAL") else "ALLOWED",
                "severity": "critical" if threat == "CRITICAL" else "warning" if threat in ("HIGH","MEDIUM") else "low",
                "lat": r.get("latitude") or geo.get("lat", 0),
                "lon": r.get("longitude") or geo.get("lon", 0),
                "latitude": r.get("latitude") or geo.get("lat", 0),
                "longitude": r.get("longitude") or geo.get("lon", 0),
                "risk_level": r.get("risk_level") or threat
            })
        return result
    except Exception: return []

@app.get("/api/net-watch/stats")
async def api_netwatch_stats():
    from .database import get_supabase
    sb = get_supabase()
    try:
        rows = sb.table("ip_log").select("*").execute().data
        flagged = [r for r in rows if r.get("flagged")]
        countries = set((r.get("geo") or {}).get("country") for r in rows if (r.get("geo") or {}).get("country"))
        return {
            "total_logins": len(rows),
            "failed_attempts": len(flagged),
            "suspicious_ips": len([r for r in rows if (r.get("geo") or {}).get("threat_level","") in ("HIGH","CRITICAL")]),
            "countries": len(countries),
            "threat_level": "ELEVATED" if flagged else "NORMAL",
        }
    except Exception: return {"total_logins":0,"failed_attempts":0,"suspicious_ips":0,"countries":0}

# ── Fraud APIs ───────────────────────────────────────────────────────────────
@app.post("/api/fraud/transaction")
async def api_create_transaction(body: TransactionCreate, request: Request):
    from .database import get_supabase, emit_event
    from .utils import now_iso
    import uuid
    txn_id = "TXN-" + str(uuid.uuid4())[:8].upper()
    ts = now_iso()
    ip = body.ip_address or get_client_ip(request)

    score_result = compute_fraud_score(
        transaction_id=txn_id, account_id=body.account_id, channel=body.channel, amount=body.amount,
        ip_address=ip, net_watch_signal=body.net_watch_signal or 0.0,
        doc_guard_signal=body.doc_guard_signal or 0.0, deep_trace_signal=body.deep_trace_signal or 0.0,
        sentinel_signal=body.sentinel_signal or 0.0, fir_warden_signal=get_account_risk_signal(body.account_id)
    )

    fraud_score = score_result["fraud_score"]
    risk_level = "CRITICAL" if fraud_score >= 85 else "HIGH" if fraud_score >= 70 else "MEDIUM" if fraud_score >= 40 else "LOW"

    txn_record = {
        "transaction_id": txn_id, "account_id": body.account_id, "amount": body.amount,
        "channel": body.channel, "ip_address": ip, "status": "flagged" if fraud_score >= 50 else "completed",
        "fraud_score": fraud_score, "risk_level": risk_level, "timestamp": ts, "created_at": ts
    }
    get_supabase().table("transactions").insert(txn_record).execute()
    return txn_record

@app.get("/api/fraud/transactions")
async def api_get_transactions(limit: int = 50, account_id: str = None, flagged: bool = False):
    from .database import get_supabase
    sb = get_supabase()
    try:
        q = sb.table("transactions").select("*").order("created_at", desc=True).limit(limit)
        if account_id: q = q.eq("account_id", account_id)
        if flagged:    q = q.eq("status", "flagged")
        data = q.execute().data
        for d in data:
            if "risk_level" not in d:
                fs = d.get("fraud_score", 0)
                d["risk_level"] = "CRITICAL" if fs >= 85 else "HIGH" if fs >= 70 else "MEDIUM" if fs >= 40 else "LOW"
        return data
    except Exception: return []

@app.get("/api/net-watch/capture")
async def api_netwatch_capture(request: Request):
    """Log IP on page load — only writes columns that exist in ip_log schema."""
    from .database import get_supabase
    from .utils import now_iso
    import httpx
    ip = get_client_ip(request)
    geo = {}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"https://ipinfo.io/{ip}/json")
            if r.status_code == 200:
                geo = r.json()
    except Exception:
        pass
    geo.setdefault("ip", ip)
    sb = get_supabase()
    try:
        sb.table("ip_log").insert({
            "ip":        geo.get("ip", ip),
            "geo":       geo,          # JSONB column — store all geo data here
            "flagged":   False,
            "count":     1,
            "context":   "page_capture",
            "logged_at": now_iso(),
        }).execute()
    except Exception:
        pass
    return {
        "status":   "ok",
        "ip":       geo.get("ip", ip),
        "city":     geo.get("city", "Unknown"),
        "country":  geo.get("country", "Unknown"),
    }

@app.get("/api/fraud/stats")
async def api_fraud_stats():
    """Aggregated fraud statistics for dashboard and external callers."""
    from .database import get_supabase
    sb = get_supabase()
    try:
        txns = sb.table("transactions").select("fraud_score,status,channel,amount,risk_level").execute().data
        if not txns:
            return {"average_fraud_score": 0, "flagged_transactions": 0, "flagged_amount_inr": 0,
                    "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                    "channel_breakdown": {}}
        flagged     = [t for t in txns if t.get("status") == "flagged"]
        avg_score   = round(sum(t.get("fraud_score") or 0 for t in txns) / len(txns), 1)
        flagged_amt = sum(t.get("amount") or 0 for t in flagged)
        dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for t in txns:
            k = t.get("risk_level", "LOW")
            if k in dist: dist[k] += 1
        ch_map = {}
        for t in txns:
            ch = t.get("channel", "Unknown")
            ch_map[ch] = ch_map.get(ch, 0) + 1
        return {
            "average_fraud_score":  avg_score,
            "flagged_transactions": len(flagged),
            "flagged_amount_inr":   round(flagged_amt, 2),
            "risk_distribution":    dist,
            "channel_breakdown":    ch_map,
        }
    except Exception as e:
        return {"error": str(e), "average_fraud_score": 0, "flagged_transactions": 0}


# ── DASHBOARD & SYSTEM ───────────────────────────────────────────────────────
@app.get("/api/dashboard/summary")
async def api_dashboard_summary():
    from .database import get_supabase
    from .blockchain import chain_connected
    sb = get_supabase()
    try:
        txns = sb.table("transactions").select("fraud_score,status").execute().data or []
        events = sb.table("events").select("id,severity").execute().data or []
        firs = sb.table("firs").select("id").execute().data or []
        
        flagged = [t for t in txns if t.get("status") == "flagged"]
        critical_alerts = [e for e in events if e.get("severity", "").lower() == "high"]
        avg_score = round(sum(t.get("fraud_score") or 0 for t in txns) / len(txns), 1) if txns else 0
        
        return {
            "total_transactions": len(txns),
            "high_risk_alerts":   len(flagged),
            "active_alerts":      len(events),
            "critical":           len(critical_alerts),
            "avg_fraud_score":    avg_score,
            "total_firs":         len(firs),
            "fused_alerts":       0, # Logic placeholder
            "chain_status":       "CONNECTED" if chain_connected() else "DISCONNECTED"
        }
    except Exception as e:
        return {"error": str(e), "total_transactions": 0, "active_alerts": 0}

@app.get("/api/chain/status")
async def api_chain_status():
    from .blockchain import get_chain_status
    return get_chain_status()

@app.get("/api/blockchain")
async def api_blockchain_ledger():
    from .database import get_supabase
    sb = get_supabase()
    try:
        rows = sb.table("blockchain_records").select("*").order("created_at", desc=True).limit(50).execute().data
        result = []
        for r in rows:
            result.append({
                "fir_id":      r.get("reference_id"),
                "tx_hash":     r.get("tx_hash"),
                "block":       r.get("block_number"),
                "status":      "ANCHORED",
                "time":        r.get("created_at", "")[:19].replace("T", " ")
            })
        return result
    except Exception: return []

@app.get("/api/health")
async def api_health():
    return {"status": "ok", "service": "kavach-unified", "timestamp": time.time()}

# ── WebSocket Proxy for Sentinel ──────────────────────────────────────────────
from fastapi import WebSocket, WebSocketDisconnect
import websockets
import asyncio

@app.websocket("/api/ws/alerts")
async def websocket_proxy_sentinel(websocket: WebSocket):
    """Proxy WebSocket alerts from internal Sentinel mount to Frontend"""
    await websocket.accept()
    # Bridging to internal mount on current port
    port = os.environ.get("PORT", "7860")
    target_url = f"ws://localhost:{port}/api/proxy/sentinel/ws/alerts"
    try:
        async with websockets.connect(target_url) as target_ws:
            async def forward_to_client():
                try:
                    async for message in target_ws:
                        await websocket.send_text(message)
                except Exception: pass
            
            async def receive_from_client():
                try:
                    async for message in websocket.iter_text():
                        await target_ws.send(message)
                except Exception: pass
            
            await asyncio.gather(forward_to_client(), receive_from_client())
    except Exception:
        pass
    finally:
        try: await websocket.close()
        except: pass