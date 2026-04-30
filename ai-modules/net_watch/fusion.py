"""
fusion.py — KAVACH Multi-Channel Fusion Engine
Detects coordinated fraud patterns across all 5 modules.

Triggers:
  COORDINATED_FRAUD    → 3+ channels signalling same account
  ACCOUNT_TAKEOVER     → Deep-Trace + Net-Watch + Doc-Guard spike
  SYNTHETIC_IDENTITY   → Doc-Guard forgery + Deep-Trace deepfake
  TRANSACTION_STORM    → High velocity transactions from flagged account
  FIR_EVIDENCE_ATTACK  → FIR tamper + unauthorized access (original logic)
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional

from fir_warden.database import get_supabase
from fir_warden.utils import now_iso

# ── Throttle: minimum seconds between same alert type ────────────────────────
THROTTLE_SECONDS = {
    "COORDINATED_FRAUD":    60,
    "ACCOUNT_TAKEOVER":     30,
    "SYNTHETIC_IDENTITY":   45,
    "TRANSACTION_STORM":    30,
    "FIR_EVIDENCE_ATTACK":  60,
}


def _is_throttled(alert_type: str) -> bool:
    """Return True if same alert type was raised within throttle window."""
    throttle = THROTTLE_SECONDS.get(alert_type, 60)
    try:
        sb = get_supabase()
        last = sb.table("alerts") \
            .select("created_at") \
            .eq("alert_type", alert_type) \
            .order("created_at", desc=True) \
            .limit(1).execute().data
        if last:
            ts = datetime.fromisoformat(last[0]["created_at"].rstrip("Z"))
            return (datetime.utcnow() - ts).total_seconds() < throttle
    except Exception:
        pass
    return False


def _raise_alert(
    alert_type: str,
    message: str,
    severity: str,
    trigger: str,
    account_id: Optional[str] = None,
    transaction_id: Optional[str] = None,
    channels: Optional[list] = None,
    fraud_score: Optional[float] = None,
):
    """Persist a fused alert to Supabase."""
    if _is_throttled(alert_type):
        return

    alert_id = str(uuid.uuid4())[:8]
    ts = now_iso()
    try:
        get_supabase().table("alerts").insert({
            "source_module": "fir_warden",
            "alert_type":     alert_type,
            "title":          alert_type.replace("_", " "),
            "description":    message,
            "severity":       severity.lower(),
            "created_at":      ts,
            "metadata": {
                "trigger":        trigger,
                "account_id":     account_id,
                "transaction_id": transaction_id,
                "channels":       channels or [],
                "fraud_score":    fraud_score,
            }
        }).execute()

        get_supabase().table("events").insert({
            "event_type": "FUSED_ALERT_GENERATED",
            "summary": f"Fused alert generated: {alert_type}",
            "detail": {
                "type": alert_type,
                "account_id": account_id,
                "trigger": trigger,
            },
            "occurred_at": ts,
        }).execute()

        print(f"🚨 FUSION [{alert_type}] account={account_id}")
    except Exception as e:
        print(f"[WARN] fusion alert insert failed: {e}")


# ── Public API ────────────────────────────────────────────────────────────────

def check_fusion(new_event_type: str):
    """
    Called after every event is emitted.
    Scans recent events and raises fusion alerts.
    """
    _check_fir_evidence_attack(new_event_type)
    _check_coordinated_fraud(new_event_type)
    _check_account_takeover(new_event_type)
    _check_synthetic_identity(new_event_type)


def check_transaction_fraud(
    transaction_id: str,
    account_id: str,
    fraud_score: float,
    channel: str,
    amount: float,
):
    """
    Called after every transaction is scored.
    Checks for TRANSACTION_STORM and COORDINATED_FRAUD.
    """
    if fraud_score >= 75:
        _check_transaction_storm(account_id, fraud_score, transaction_id)

    # If high-risk transaction, emit event for cross-module fusion
    if fraud_score >= 50:
        try:
            get_supabase().table("events").insert({
                "event_type":     "HIGH_RISK_TRANSACTION",
                "summary":       f"High risk transaction: {transaction_id}",
                "occurred_at":      now_iso(),
                "detail": {
                    "confidence":     round(fraud_score / 100, 2),
                    "account_id":     account_id,
                    "transaction_id": transaction_id,
                    "amount":         amount,
                    "channel":        channel,
                    "score":          fraud_score,
                },
            }).execute()
        except Exception as e:
            print(f"[WARN] event insert failed: {e}")


def check_ddos_fusion(ip: str, fir_id: str):
    """Unauthorized access + DDoS → immediate CRITICAL (original logic kept)."""
    _raise_alert(
        alert_type="FIR_EVIDENCE_ATTACK",
        message=f"HIGH RISK: Unauthorized FIR access + DDoS flooding from {ip}",
        severity="CRITICAL",
        trigger="DDOS+UNAUTH",
    )


# ── Internal fusion checks ────────────────────────────────────────────────────

def _check_fir_evidence_attack(new_type: str):
    """FIR_TAMPER + UNAUTH_ACCESS within last 30 events."""
    try:
        sb = get_supabase()
        recent = sb.table("events").select("event_type").order("occurred_at", desc=True).limit(30).execute().data
        types = {r["event_type"] for r in recent}
        if "FIR_TAMPER" in types and "UNAUTH_ACCESS" in types:
            _raise_alert(
                alert_type="FIR_EVIDENCE_ATTACK",
                message="FIR tampering combined with unauthorized access — potential evidence manipulation.",
                severity="CRITICAL",
                trigger=new_type,
            )
    except Exception as e:
        print(f"[WARN] _check_fir_evidence_attack: {e}")


def _check_coordinated_fraud(new_type: str):
    """
    COORDINATED_FRAUD: 3+ different fraud channels signalling same account
    within last 10 minutes.
    """
    FRAUD_EVENT_TYPES = {
        "HIGH_RISK_TRANSACTION",  # FIR-Warden / transaction scorer
        "UNAUTH_ACCESS",          # Net-Watch
        "DDOS_SUSPECTED",         # Net-Watch
        "FIR_TAMPER",             # FIR-Warden
        "DEEPFAKE_DETECTED",      # Deep-Trace
        "KYC_FRAUD",              # Doc-Guard
        "SENTINEL_ALERT",         # Crowd Sentinel
    }
    try:
        sb = get_supabase()
        cutoff = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        recent = sb.table("events") \
            .select("event_type, detail") \
            .in_("event_type", list(FRAUD_EVENT_TYPES)) \
            .gte("occurred_at", cutoff) \
            .execute().data

        # Group by account_id — find accounts with 3+ distinct channel signals
        from collections import defaultdict
        account_signals = defaultdict(set)
        for ev in recent:
            acc = ev.get("detail", {}).get("account_id")
            if acc:
                account_signals[acc].add(ev["event_type"])

        for account_id, signals in account_signals.items():
            if len(signals) >= 3:
                _raise_alert(
                    alert_type="COORDINATED_FRAUD",
                    message=f"Coordinated fraud detected on account {account_id}: {len(signals)} channels signalling simultaneously.",
                    severity="CRITICAL",
                    trigger=new_type,
                    account_id=account_id,
                    channels=list(signals),
                )
    except Exception as e:
        print(f"[WARN] _check_coordinated_fraud: {e}")


def _check_account_takeover(new_type: str):
    """
    ACCOUNT_TAKEOVER: Deep-Trace deepfake + Net-Watch IP anomaly + Doc-Guard flag
    all hit within 5 minutes — classic ATO pattern.
    """
    ATO_SIGNALS = {"DEEPFAKE_DETECTED", "UNAUTH_ACCESS", "KYC_FRAUD"}
    try:
        sb = get_supabase()
        cutoff = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        recent = sb.table("events") \
            .select("event_type") \
            .in_("event_type", list(ATO_SIGNALS)) \
            .gte("occurred_at", cutoff) \
            .execute().data

        found = {r["event_type"] for r in recent}
        if ATO_SIGNALS.issubset(found):
            _raise_alert(
                alert_type="ACCOUNT_TAKEOVER",
                message="Account Takeover pattern: Deepfake identity + IP anomaly + KYC forgery detected within 5 minutes.",
                severity="CRITICAL",
                trigger=new_type,
                channels=["Deep-Trace", "Net-Watch", "Doc-Guard"],
            )
    except Exception as e:
        print(f"[WARN] _check_account_takeover: {e}")


def _check_synthetic_identity(new_type: str):
    """
    SYNTHETIC_IDENTITY: Doc-Guard KYC forgery + Deep-Trace deepfake 
    — manufactured identity fraud.
    """
    try:
        sb = get_supabase()
        cutoff = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
        recent = sb.table("events") \
            .select("event_type") \
            .in_("event_type", ["KYC_FRAUD", "DEEPFAKE_DETECTED"]) \
            .gte("occurred_at", cutoff) \
            .execute().data

        found = {r["event_type"] for r in recent}
        if "KYC_FRAUD" in found and "DEEPFAKE_DETECTED" in found:
            _raise_alert(
                alert_type="SYNTHETIC_IDENTITY",
                message="Synthetic Identity fraud: Forged KYC document + Deepfake biometric detected — likely fabricated account.",
                severity="HIGH",
                trigger=new_type,
                channels=["Doc-Guard", "Deep-Trace"],
            )
    except Exception as e:
        print(f"[WARN] _check_synthetic_identity: {e}")


def _check_transaction_storm(account_id: str, fraud_score: float, transaction_id: str):
    """
    TRANSACTION_STORM: Multiple high-score transactions from same account
    in a short window.
    """
    try:
        sb = get_supabase()
        cutoff = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        recent_high = sb.table("transactions") \
            .select("id") \
            .eq("account_id", account_id) \
            .gte("fraud_score", 60) \
            .gte("timestamp", cutoff) \
            .execute().data

        if len(recent_high) >= 3:
            _raise_alert(
                alert_type="TRANSACTION_STORM",
                message=f"Transaction storm on account {account_id}: {len(recent_high)} high-risk transactions in 5 minutes.",
                severity="HIGH",
                trigger="HIGH_RISK_TRANSACTION",
                account_id=account_id,
                transaction_id=transaction_id,
                fraud_score=fraud_score,
                channels=["FIR-Warden"],
            )
    except Exception as e:
        print(f"[WARN] _check_transaction_storm: {e}")
