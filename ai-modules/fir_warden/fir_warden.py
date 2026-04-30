"""
fir_warden.py
FIR-Warden module.
Responsibility: High-integrity FIR lifecycle management aligned with Supabase schema.
"""

import json
import uuid

from .database   import emit_event, log_audit, get_supabase
from .blockchain import anchor_to_blockchain, verify_on_chain
from .utils      import sha256, now_iso, diff_dicts

SYSTEM_AGENT_ID = "00000000-0000-0000-0000-000000000000"

# ── Create ────────────────────────────────────────────────────────────────────

def create_fir(data: dict) -> dict:
    """
    Register a new FIR with strict schema compliance.
    """
    db_id    = str(uuid.uuid4())
    fir_num  = data.get("fir_number") or ("FIR-" + str(uuid.uuid4())[:8].upper())
    fir_hash = sha256(json.dumps(data, sort_keys=True))
    ts       = now_iso()

    sb = get_supabase()
    
    # Try to find a real officer, otherwise use System Agent
    officer_id = SYSTEM_AGENT_ID
    try:
        users = sb.table("users").select("id").limit(1).execute().data
        if users:
            officer_id = users[0]["id"]
    except:
        pass

    # Resolve officer_id: If it's a badge number, look up the UUID
    input_officer = data.get("officer_id") or data.get("officer_badge")
    filed_by = officer_id # default to system/first user

    if input_officer:
        # Check if it's already a UUID (regex for standard UUID format)
        import re
        uuid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        if uuid_regex.match(str(input_officer)):
            filed_by = input_officer
        else:
            # Try to look up by badge_number
            try:
                found = sb.table("users").select("id").eq("badge_number", str(input_officer)).execute().data
                if found:
                    filed_by = found[0]["id"]
                else:
                    print(f"[FIR-Warden] Warning: Badge '{input_officer}' not found. Using default.")
            except:
                pass

    # Map frontend types to DB-supported categories
    raw_type = (data.get("incident_type") or data.get("category") or "OTHER").upper()
    category_map = {
        "PHISHING":         "fraud",
        "CARD_CLONING":     "fraud",
        "UPI_FRAUD":        "fraud",
        "WIRE_FRAUD":       "fraud",
        "IDENTITY_THEFT":   "cyber_crime",
        "COORDINATED_ATTACK": "other",
        "SENTINEL_ALERT":    "other",
        "OTHER":            "other"
    }
    db_category = category_map.get(raw_type, "other")

    # Prepare schema-compliant entry for 'firs' table
    fir_entry = {
        "id":                db_id,
        "fir_number":        fir_num,
        "station_code":      data.get("station_code", "STN-BLR-01"),
        "district":          data.get("district", "Bengaluru"),
        "state":             data.get("state", "Karnataka"),
        "filed_by":          filed_by,
        "complainant_name":  data.get("complainant") or data.get("complainant_name", "AI Sentinel System"),
        "incident_date":     data.get("date_of_incident") or now_iso().split("T")[0],
        "incident_location": data.get("location", "Camera Feed 01"),
        "category":          db_category,
        "severity":          data.get("severity", "critical"),
        "description":       data.get("description", "Automated forensic report."),
        "status":            "open",
        "blockchain_hash":   fir_hash,
        "priority":          data.get("priority", "LOW"),
        "risk_score":        data.get("risk_score", 0),
        "image_url":         data.get("image_url")
    }

    try:
        sb.table("firs").insert(fir_entry).execute()
    except Exception as e:
        print(f"[FIR-Warden] DB Error (firs): {e}")
        raise

    # Insert into 'fir_versions' table
    try:
        sb.table("fir_versions").insert({
            "fir_id":         db_id,
            "version_number": 1,
            "changed_by":     officer_id,
            "change_type":    "created",
            "diff_snapshot":  data,
            "change_summary": "Initial AI registration",
            "created_at":     ts
        }).execute()
    except Exception as e:
        print(f"[FIR-Warden] DB Error (fir_versions): {e}")

    log_audit("FIR_CREATED", {"fir_id": db_id, "fir_number": fir_num, "hash": fir_hash})
    emit_event("FIR_CREATED", fir_entry["incident_location"], 1.0, {
        "fir_id":   db_id,
        "fir_num":  fir_num,
        "type":     fir_entry["category"],
        "severity": fir_entry["severity"],
        "message":  f"FIR {fir_num} generated for {fir_entry['category']}"
    })
    
    tx = anchor_to_blockchain(db_id, 1, fir_hash)
    return {
        "fir_id":      db_id,
        "fir_number":  fir_num,
        "fir_hash":    fir_hash,
        "version":     1,
        "tx_hash":     tx.get("tx_hash") if tx else None,
        "blockchain":  tx
    }


# ── List ──────────────────────────────────────────────────────────────────────

def list_firs() -> list:
    """
    Return summary of all FIRs (latest version per FIR).
    """
    sb = get_supabase()
    
    # Fetch all versions and meta
    versions = sb.table("fir_versions").select("*").execute().data
    firs_meta = sb.table("firs").select("*").execute().data
    
    if not versions or not firs_meta:
        return []

    # Map firs by ID
    meta_dict = {f["id"]: f for f in firs_meta}
    
    # Group by fir_id to find latest version
    latest_versions = {}
    for v in versions:
        fid = v["fir_id"]
        if fid not in latest_versions or v["version_number"] > latest_versions[fid]["version_number"]:
            latest_versions[fid] = v

    result = []
    # Sort by created_at desc
    sorted_fids = sorted(latest_versions.keys(), key=lambda f: meta_dict.get(f, {}).get("created_at", ""), reverse=True)
    
    for fid in sorted_fids:
        latest = latest_versions[fid]
        meta = meta_dict.get(fid, {})
        result.append({
            "id":            fid,
            "fir_id":        fid,
            "fir_number":    meta.get("fir_number"),
            "version":       latest["version_number"],
            "complainant":   meta.get("complainant_name"),
            "incident_type": meta.get("category"),
            "location":      meta.get("incident_location"),
            "officer_id":    meta.get("filed_by"),
            "status":        meta.get("status"),
            "created_at":    meta.get("created_at"),
            "date_of_incident": meta.get("incident_date"),
            "fir_hash":      meta.get("blockchain_hash"),
        })
    return result


# ── Get ───────────────────────────────────────────────────────────────────────

def get_fir(fir_id: str) -> dict | None:
    """
    Return full FIR with all versions.
    """
    sb = get_supabase()
    fir_res = sb.table("firs").select("*").eq("id", fir_id).execute().data
    if not fir_res:
        return None
        
    versions = sb.table("fir_versions").select("*").eq("fir_id", fir_id).order("version_number", desc=False).execute().data

    return {
        "metadata": fir_res[0],
        "versions": [
            {
                "version":    v["version_number"],
                "data":       v["diff_snapshot"],
                "change":     v["change_type"],
                "summary":    v["change_summary"],
                "created_at": v["created_at"],
            }
            for v in versions
        ],
    }


# ── Edit ──────────────────────────────────────────────────────────────────────

def edit_fir(fir_id: str, updates: dict) -> dict | None:
    """
    Apply field updates and record a new version.
    """
    sb = get_supabase()
    fir_res = sb.table("firs").select("*").eq("id", fir_id).execute().data
    if not fir_res:
        return None
        
    versions = sb.table("fir_versions").select("*").eq("fir_id", fir_id).order("version_number", desc=False).execute().data
    if not versions:
        return None
        
    latest = versions[-1]
    old_data = latest["diff_snapshot"]
    new_data = {**old_data, **{k: v for k, v in updates.items() if v is not None}}
    
    new_version = latest["version_number"] + 1
    ts = now_iso()
    
    # Update main table status if provided
    if "status" in updates:
        sb.table("firs").update({"status": updates["status"]}).eq("id", fir_id).execute()

    # Insert new version
    sb.table("fir_versions").insert({
        "fir_id":         fir_id,
        "version_number": new_version,
        "changed_by":     SYSTEM_AGENT_ID,
        "change_type":    "updated",
        "diff_snapshot":  new_data,
        "change_summary": "Manual update via dashboard",
        "created_at":     ts
    }).execute()

    new_hash = sha256(json.dumps(new_data, sort_keys=True))
    tx = anchor_to_blockchain(fir_id, new_version, new_hash)

    return {
        "fir_id":   fir_id,
        "version":  new_version,
        "hash":     new_hash,
        "blockchain": tx
    }


# ── Verify ────────────────────────────────────────────────────────────────────

def verify_fir(fir_id: str) -> dict | None:
    """
    Verify integrity against blockchain.
    """
    sb = get_supabase()
    fir_res = sb.table("firs").select("*").eq("id", fir_id).execute().data
    if not fir_res:
        return None
        
    on_chain_res = sb.table("blockchain_records").select("*").eq("reference_id", fir_id).eq("record_type", "fir").execute().data
    on_chain = on_chain_res[0] if on_chain_res else None
    
    current_hash = fir_res[0].get("blockchain_hash")
    on_chain_hash = on_chain["data_hash"] if on_chain else None
    
    verified = (current_hash == on_chain_hash) if on_chain_hash else False

    return {
        "fir_id":         fir_id,
        "db_hash":        current_hash,
        "chain_hash":     on_chain_hash,
        "verified":       verified,
        "status":         "SECURE" if verified else "UNVERIFIED",
        "tx_hash":        on_chain["tx_hash"] if on_chain else None
    }
