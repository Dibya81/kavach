import hashlib, cv2, numpy as np
from datetime import datetime
from typing import Optional, Dict, Any
from .ocr_utils import extract_text, normalize_text
from .diff_utils import compute_diff, similarity_ratio
from fir_warden.database import get_supabase


def get_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _image_similarity(bytes_a: bytes, bytes_b: bytes) -> dict:
    """
    Compare two document images using SSIM + pixel diff.
    Returns: {ssim_score, diff_regions, visual_tampered}
    """
    try:
        from skimage.metrics import structural_similarity as ssim

        def to_gray(b):
            arr  = np.frombuffer(b, np.uint8)
            img  = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is None:
                return None
            # Resize to fixed size for comparison
            img  = cv2.resize(img, (800, 600))
            return cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        gray_a = to_gray(bytes_a)
        gray_b = to_gray(bytes_b)

        if gray_a is None or gray_b is None:
            return {"ssim_score": 1.0, "diff_regions": 0, "visual_tampered": False}

        score, diff = ssim(gray_a, gray_b, full=True)
        diff = (diff * 255).astype("uint8")

        # Find changed regions
        thresh    = cv2.threshold(diff, 200, 255, cv2.THRESH_BINARY_INV)[1]
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        significant = [c for c in contours if cv2.contourArea(c) > 500]

        return {
            "ssim_score":     round(float(score), 4),
            "diff_regions":   len(significant),
            "visual_tampered": score < 0.92 or len(significant) > 3,
        }
    except ImportError:
        # skimage not available — use pixel MSE only
        try:
            def to_arr(b):
                arr = np.frombuffer(b, np.uint8)
                img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
                return cv2.resize(img, (800, 600)) if img is not None else None

            a = to_arr(bytes_a)
            b = to_arr(bytes_b)
            if a is None or b is None:
                return {"ssim_score": 1.0, "diff_regions": 0, "visual_tampered": False}
            mse = float(np.mean((a.astype(float) - b.astype(float)) ** 2))
            score = max(0.0, 1.0 - mse / 10000)
            return {
                "ssim_score":     round(score, 4),
                "diff_regions":   0,
                "visual_tampered": score < 0.92,
            }
        except Exception:
            return {"ssim_score": 1.0, "diff_regions": 0, "visual_tampered": False}
    except Exception as e:
        print(f"[DocGuard] Image comparison failed: {e}")
        return {"ssim_score": 1.0, "diff_regions": 0, "visual_tampered": False}


def upload_document(doc_id: str, file_bytes: bytes, filename: str) -> Dict[str, Any]:
    raw_text  = extract_text(file_bytes, filename)
    norm_text = normalize_text(raw_text)
    doc_hash  = get_hash(norm_text)
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Store raw bytes as hex for later image comparison
    image_hex = file_bytes.hex() if filename.lower().endswith(
        ('.jpg', '.jpeg', '.png', '.bmp')) else None

    sb = get_supabase()
    try:
        sb.table("kyc_documents").upsert({
            "doc_id":        doc_id,
            "filename":      filename,
            "original_text": norm_text,
            "hash":          doc_hash,
            "image_data":    image_hex,   # stored for SSIM comparison
            "timestamp":     timestamp,
        }, on_conflict="doc_id").execute()
    except Exception as e:
        print(f"[DocGuard] Store failed: {e}")

    return {
        "doc_id":    doc_id,
        "hash":      doc_hash,
        "timestamp": timestamp,
        "message":   "Document registered successfully",
    }


def verify_document(doc_id: str, file_bytes: bytes, filename: str) -> Optional[Dict[str, Any]]:
    sb  = get_supabase()
    res = sb.table("kyc_documents").select("*").eq("doc_id", doc_id).execute().data
    if not res:
        return None
    baseline = res[0]

    # ── Text comparison ────────────────────────────────────────────────────
    raw_text  = extract_text(file_bytes, filename)
    norm_text = normalize_text(raw_text)
    new_hash  = get_hash(norm_text)
    text_tampered  = new_hash != baseline["hash"]
    text_similarity = 1.0
    differences     = []

    if text_tampered:
        differences     = compute_diff(baseline["original_text"], norm_text)
        text_similarity = similarity_ratio(baseline["original_text"], norm_text)

    # ── Image comparison (SSIM) ────────────────────────────────────────────
    image_result = {"ssim_score": 1.0, "diff_regions": 0, "visual_tampered": False}
    is_image = filename.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp'))

    if is_image and baseline.get("image_data"):
        try:
            original_bytes = bytes.fromhex(baseline["image_data"])
            image_result   = _image_similarity(original_bytes, file_bytes)
        except Exception as e:
            print(f"[DocGuard] SSIM failed: {e}")

    # ── Combined verdict ───────────────────────────────────────────────────
    is_tampered     = text_tampered or image_result["visual_tampered"]
    final_similarity = round(
        (text_similarity * 0.5 + image_result["ssim_score"] * 0.5) * 100, 1
    ) if is_image else round(text_similarity * 100, 1)

    # Fraud risk signal for Fraud Monitor (0.0–1.0)
    fraud_signal = round(1.0 - (final_similarity / 100), 3)

    # Try to push to Fraud Monitor
    try:
        import httpx
        httpx.post("http://localhost:8000/api/fraud/deeptrace-result", json={
            "source":            "doc-guard",
            "doc_id":            doc_id,
            "verdict":           "TAMPERED" if is_tampered else "CLEAN",
            "fraud_risk_signal": fraud_signal,
            "confidence":        fraud_signal,
        }, timeout=2.0)
    except Exception:
        pass

    return {
        "doc_id":            doc_id,
        "status":            "Tampered" if is_tampered else "Valid",
        "original_hash":     baseline["hash"],
        "current_hash":      new_hash,
        "similarity":        final_similarity,
        "fraud_signal":      fraud_signal,
        "text_tampered":     text_tampered,
        "visual_tampered":   image_result["visual_tampered"],
        "ssim_score":        image_result["ssim_score"],
        "diff_regions":      image_result["diff_regions"],
        "differences":       differences[:10],  # top 10 changes
        "stored_at":         baseline["timestamp"],
    }


def list_documents() -> list:
    """Return summary of all stored document baselines."""
    sb = get_supabase()
    return sb.table("kyc_documents").select("doc_id, filename, hash, timestamp").execute().data
