"""
fraud_scorer.py
KAVACH Fraud Scoring Engine — combines signals from all 5 modules.
Returns fraud_score (0–100), risk_level, explanation.
"""

from typing import Optional
from .database import get_supabase
from .utils import now_iso

# ── Weight configuration (must sum to 100) ───────────────────────────────────
WEIGHTS = {
    "net_watch":   25,   # IP risk, VPN, DDoS, geo-anomaly
    "doc_guard":   20,   # KYC document tamper
    "deep_trace":  20,   # Deepfake identity
    "sentinel":    15,   # ATM crowd / weapon / loitering
    "fir_warden":  20,   # Transaction velocity, FIR anomaly
}

def compute_fraud_score(
    transaction_id: str,
    account_id: str,
    channel: str,
    amount: float,
    ip_address: Optional[str] = None,
    # Individual module signals (0.0 – 1.0 confidence)
    net_watch_signal: float = 0.0,
    doc_guard_signal: float = 0.0,
    deep_trace_signal: float = 0.0,
    sentinel_signal: float = 0.0,
    fir_warden_signal: float = 0.0,
) -> dict:
    """
    Compute unified fraud score from all module signals.
    
    Each signal is a float 0.0 (clean) to 1.0 (definite fraud).
    Returns fraud_score 0-100, risk_level, explanation list.
    """
    signals = {
        "net_watch":  net_watch_signal,
        "doc_guard":  doc_guard_signal,
        "deep_trace": deep_trace_signal,
        "sentinel":   sentinel_signal,
        "fir_warden": fir_warden_signal,
    }

    # ── Weighted score ────────────────────────────────────────────────────────
    raw_score = sum(
        signals[module] * WEIGHTS[module]
        for module in signals
    )
    # raw_score is already 0-100 (since weights sum to 100 and signals are 0-1)
    
    # ── Amount boost: large transactions get a risk multiplier ────────────────
    if amount > 100000:       # > 1L INR
        raw_score = min(100, raw_score * 1.15)
    elif amount > 500000:     # > 5L INR
        raw_score = min(100, raw_score * 1.30)

    # ── Channel risk boost ────────────────────────────────────────────────────
    channel_boost = {
        "ATM": 1.10,
        "online": 1.05,
        "UPI": 1.0,
        "NEFT": 1.0,
        "RTGS": 0.95,   # RTGS is slower/more monitored
        "POS": 1.0,
        "mobile": 1.05,
    }
    raw_score = min(100, raw_score * channel_boost.get(channel, 1.0))

    final_score = round(raw_score, 2)

    # ── Risk level bucketing ──────────────────────────────────────────────────
    if final_score >= 75:
        risk_level = "CRITICAL"
    elif final_score >= 50:
        risk_level = "HIGH"
    elif final_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ── Human-readable explanation ────────────────────────────────────────────
    explanation = []
    if net_watch_signal > 0.3:
        explanation.append(f"Net-Watch: Suspicious IP activity (score {net_watch_signal:.0%})")
    if doc_guard_signal > 0.3:
        explanation.append(f"Doc-Guard: KYC document anomaly detected (score {doc_guard_signal:.0%})")
    if deep_trace_signal > 0.3:
        explanation.append(f"Deep-Trace: Biometric/deepfake risk (score {deep_trace_signal:.0%})")
    if sentinel_signal > 0.3:
        explanation.append(f"Crowd-Sentinel: ATM surveillance alert (score {sentinel_signal:.0%})")
    if fir_warden_signal > 0.3:
        explanation.append(f"FIR-Warden: Transaction pattern anomaly (score {fir_warden_signal:.0%})")
    if amount > 100000:
        explanation.append(f"High-value transaction: ₹{amount:,.0f}")
    if not explanation:
        explanation.append("No significant fraud signals detected")

    # ── Persist score ─────────────────────────────────────────────────────────
    try:
        get_supabase().table("fraud_scores").insert({
            "transaction_id":   transaction_id,
            "account_id":       account_id,
            "net_watch_score":  round(net_watch_signal * WEIGHTS["net_watch"], 2),
            "doc_guard_score":  round(doc_guard_signal * WEIGHTS["doc_guard"], 2),
            "deep_trace_score": round(deep_trace_signal * WEIGHTS["deep_trace"], 2),
            "sentinel_score":   round(sentinel_signal * WEIGHTS["sentinel"], 2),
            "fir_warden_score": round(fir_warden_signal * WEIGHTS["fir_warden"], 2),
            "final_score":      final_score,
            "risk_level":       risk_level,
            "explanation":      explanation,
            "created_at":       now_iso(),
        }).execute()
    except Exception as e:
        print(f"[WARN] fraud_scores insert failed: {e}")

    return {
        "transaction_id": transaction_id,
        "account_id":     account_id,
        "fraud_score":    final_score,
        "risk_level":     risk_level,
        "explanation":    explanation,
        "signals": {
            "net_watch":  net_watch_signal,
            "doc_guard":  doc_guard_signal,
            "deep_trace": deep_trace_signal,
            "sentinel":   sentinel_signal,
            "fir_warden": fir_warden_signal,
        }
    }


def get_account_risk_signal(account_id: str) -> float:
    """
    Derive a fir_warden signal from this account's transaction history.
    High velocity, repeated flags = higher signal.
    """
    try:
        sb = get_supabase()
        # Last 24h transactions for this account
        recent = sb.table("transactions") \
            .select("fraud_score, status, amount") \
            .eq("account_id", account_id) \
            .gte("timestamp", "NOW() - INTERVAL '24 hours'") \
            .execute().data

        if not recent:
            return 0.0

        flagged = [t for t in recent if t.get("status") == "flagged"]
        avg_score = sum(t.get("fraud_score") or 0 for t in recent) / len(recent)
        
        # Velocity: more than 10 txns/hour is suspicious
        velocity_signal = min(1.0, len(recent) / 50)
        flagged_signal  = min(1.0, len(flagged) / 3)
        score_signal    = avg_score / 100

        return round((velocity_signal * 0.3 + flagged_signal * 0.5 + score_signal * 0.2), 3)
    except Exception:
        return 0.0
