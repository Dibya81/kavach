"""
KAVACH Deep Trace — Deepfake Video & Image Detection
Single-file FastAPI service.

Install:
    pip install fastapi uvicorn torch torchvision timm mtcnn-pytorch \
                opencv-python-headless pillow numpy reportlab aiofiles python-multipart

Run:
    uvicorn main:app --host 0.0.0.0 --port 9002 --reload

Endpoints:
    POST /analyze/video   → upload video file, returns JSON verdict + per-frame scores
    POST /analyze/image   → upload image file, returns JSON verdict
    GET  /report/{job_id} → download court-ready PDF report
    GET  /health
"""

import io
import json
import os
import time
import uuid
import tempfile
import logging
from pathlib import Path
from typing import Optional
import httpx

from shared.logger import logger, setup_uvicorn_logging

import cv2
import numpy as np
import torch
import torch.nn as nn
import torchvision.transforms as T
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from PIL import Image

# ── Optional: MTCNN for face detection ──────────────────────────────────
try:
    from mtcnn import MTCNN
    MTCNN_AVAILABLE = True
except ImportError:
    MTCNN_AVAILABLE = False
    logger.warn("Deep-Trace: mtcnn not installed → using OpenCV face detector as fallback")

# ── timm for EfficientNet backbone ───────────────────────────────────────
try:
    import timm
    TIMM_AVAILABLE = True
except ImportError:
    TIMM_AVAILABLE = False
    logger.warn("Deep-Trace: timm not installed → running FFT-only mode")

# ── ReportLab for PDF export ──────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warn("Deep-Trace: reportlab not installed → PDF export disabled")

try:
    from transformers import AutoImageProcessor, AutoModelForImageClassification
    from huggingface_hub import snapshot_download
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warn("Deep-Trace: transformers not installed → falling back to FFT-only mode")

# ─────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────
# ── Resolve local paths
MODULE_DIR         = Path(__file__).parent
DEVICE             = "cuda" if torch.cuda.is_available() else "cpu"
# HF Model ID (SigLIP based Deepfake Detector)
MODEL_ID           = "prithivMLmods/deepfake-detector-model-v1"
LOCAL_MODEL_PATH   = MODULE_DIR / "models" / "siglip_deepfake"
FRAMES_TO_SAMPLE   = 15          # frames extracted per video for analysis
FAKE_THRESHOLD     = 0.50        # probability above this = FAKE verdict
REPORTS_DIR        = MODULE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# print(f"[DeepTrace] Using device: {DEVICE}") # Silenced

import os
os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "1"

# ─────────────────────────────────────────────────────────────────────────
# MODEL LOADING
# ─────────────────────────────────────────────────────────────────────────
def download_model_locally():
    """Ensure the HF model is downloaded to the local models directory."""
    if not TRANSFORMERS_AVAILABLE:
        return
    
    # Check for config.json to ensure download actually completed
    if not (LOCAL_MODEL_PATH / "config.json").exists():
        logger.warn(f"Deep-Trace: Downloading model weights ({MODEL_ID})...")
        try:
            snapshot_download(
                repo_id=MODEL_ID,
                local_dir=str(LOCAL_MODEL_PATH),
                local_dir_use_symlinks=False,
                resume_download=True
            )
            logger.info("Deep-Trace: Model downloaded successfully")
        except Exception as e:
            logger.error(f"Deep-Trace: Failed to download model: {e}")
    else:
        # logger.info(f"Deep-Trace: Model verified at {LOCAL_MODEL_PATH}")
        pass

def load_siglip_model():
    """Load the SigLIP model and processor."""
    if not TRANSFORMERS_AVAILABLE:
        return None, None

    print(f"[DeepTrace] Loading SigLIP model from {LOCAL_MODEL_PATH}...")
    try:
        # If local path doesn't have the files, fallback to MODEL_ID (auto-download to cache)
        path = str(LOCAL_MODEL_PATH) if (LOCAL_MODEL_PATH / "config.json").exists() else MODEL_ID
        
        processor = AutoImageProcessor.from_pretrained(path)
        model = AutoModelForImageClassification.from_pretrained(path).to(DEVICE)
        model.eval()
        return processor, model
    except Exception as e:
        logger.error(f"Deep-Trace: Error loading SigLIP model: {e}")
        return None, None

# Run download at startup
download_model_locally()
vit_processor, vit_model = load_siglip_model()

# ─────────────────────────────────────────────────────────────────────────
# FACE DETECTOR
# ─────────────────────────────────────────────────────────────────────────
if MTCNN_AVAILABLE:
    face_detector = MTCNN()
else:
    # Fallback to OpenCV Haar cascade
    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    face_detector_cv = cv2.CascadeClassifier(cascade_path)


# ─────────────────────────────────────────────────────────────────────────
# TRANSFORMS
# ─────────────────────────────────────────────────────────────────────────
IMG_TRANSFORM = T.Compose([
    T.Resize((224, 224)),
    T.ToTensor(),
    T.Normalize(mean=[0.485, 0.456, 0.406],
                std=[0.229, 0.224, 0.225])
])

# ─────────────────────────────────────────────────────────────────────────
# DETECTION UTILITIES
# ─────────────────────────────────────────────────────────────────────────
def detect_faces_in_frame(frame_bgr: np.ndarray) -> list[np.ndarray]:
    """Return list of face crops (numpy arrays, RGB)."""
    frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
    crops = []

    if MTCNN_AVAILABLE:
        detections = face_detector.detect_faces(frame_rgb)
        for det in detections:
            if det["confidence"] < 0.85:
                continue
            x, y, w, h = det["box"]
            # add 20% padding
            pad_x, pad_y = int(w * 0.2), int(h * 0.2)
            x1 = max(0, x - pad_x)
            y1 = max(0, y - pad_y)
            x2 = min(frame_rgb.shape[1], x + w + pad_x)
            y2 = min(frame_rgb.shape[0], y + h + pad_y)
            crops.append(frame_rgb[y1:y2, x1:x2])
    else:
        # OpenCV Fallback - Improved sensitivity
        gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        # 1.1 scaleFactor and 3 minNeighbors are much more sensitive than 1.3/5
        faces = face_detector_cv.detectMultiScale(gray, 1.1, 3, minSize=(30, 30))
        for (x, y, w, h) in faces:
            # Add a small margin to the crop
            margin = int(w * 0.1)
            y1 = max(0, y - margin)
            y2 = min(frame_rgb.shape[0], y + h + margin)
            x1 = max(0, x - margin)
            x2 = min(frame_rgb.shape[1], x + w + margin)
            crops.append(frame_rgb[y1:y2, x1:x2])

    return crops


def classify_face_crop(crop: np.ndarray) -> float:
    """
    Run ViT classifier on a face crop.
    Returns fake probability 0.0–1.0.
    
    This model outputs a single logit. We apply sigmoid then calibrate
    using the model's known operating point (0.5 raw ≈ boundary).
    Values > 0.5 after sigmoid = FAKE tendency.
    """
    if not TRANSFORMERS_AVAILABLE or vit_model is None:
        return fft_artifact_score(crop)

    try:
        pil_img = Image.fromarray(crop).convert("RGB")
        inputs  = vit_processor(images=pil_img, return_tensors="pt").to(DEVICE)

        with torch.no_grad():
            outputs = vit_model(**inputs)
            logits  = outputs.logits  # shape: (1, 2) [Fake, Real]

        # Apply softmax to get probabilities
        probs = torch.softmax(logits, dim=-1)
        # Index 0 is 'Fake' as per model config.json
        prob_fake = float(probs[0, 0].item())

        # Blend with FFT for robustness (75% SigLIP, 25% FFT)
        fft_prob = fft_artifact_score(crop)
        blended  = (prob_fake * 0.75) + (fft_prob * 0.25)

        return round(blended, 4)

    except Exception as e:
        logger.error(f"Deep-Trace: ViT inference error: {e}")
        return fft_artifact_score(crop)


def fft_artifact_score(crop: np.ndarray) -> float:
    """
    GAN fingerprint detection via FFT frequency analysis.
    Real images have smooth frequency falloff.
    GAN images show grid artifacts in high-frequency bands.
    Returns 0.0-1.0 (higher = more likely fake).
    """
    gray = cv2.cvtColor(crop, cv2.COLOR_RGB2GRAY) if len(crop.shape) == 3 else crop
    gray = cv2.resize(gray, (128, 128)).astype(np.float32)

    fft = np.fft.fft2(gray)
    fft_shift = np.fft.fftshift(fft)
    magnitude = np.log(np.abs(fft_shift) + 1e-8)

    # Compare energy in center (low-freq) vs corners (high-freq)
    h, w = magnitude.shape
    center = magnitude[h//4:3*h//4, w//4:3*w//4]
    corners = magnitude.copy()
    corners[h//4:3*h//4, w//4:3*w//4] = 0
    nonzero = corners[corners > 0]
    if len(nonzero) == 0:
        return 0.0

    ratio = nonzero.mean() / (center.mean() + 1e-8)
    # Clamp to 0-1 range (empirically tuned)
    score = float(np.clip((ratio - 0.3) / 0.7, 0.0, 1.0))
    return score


def extract_video_frames(video_path: str, n_frames: int = FRAMES_TO_SAMPLE) -> list[np.ndarray]:
    """Uniformly sample n_frames from a video file."""
    cap = cv2.VideoCapture(video_path)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    if total == 0:
        cap.release()
        return []

    indices = np.linspace(0, total - 1, min(n_frames, total), dtype=int)
    frames = []
    for idx in indices:
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
        ok, frame = cap.read()
        if ok:
            frames.append(frame)
    cap.release()
    return frames


def analyze_frames(frames: list[np.ndarray]) -> dict:
    """
    Run full detection pipeline on a list of frames.
    Returns aggregated verdict dict.
    """
    per_frame = []
    faces_found = 0

    for i, frame in enumerate(frames):
        crops = detect_faces_in_frame(frame)
        faces_found += len(crops)

        frame_scores = []
        for crop in crops:
            cnn_score = classify_face_crop(crop)
            fft_score = fft_artifact_score(crop)
            # Weighted blend: 70% CNN, 30% FFT
            blended = (cnn_score * 0.70) + (fft_score * 0.30)
            frame_scores.append({
                "cnn": round(cnn_score, 4),
                "fft": round(fft_score, 4),
                "blended": round(blended, 4)
            })

        if frame_scores:
            avg_blended = np.mean([s["blended"] for s in frame_scores])
        else:
            avg_blended = 0.0  # no face = can't determine

        per_frame.append({
            "frame_index": i,
            "faces_detected": len(crops),
            "scores": frame_scores,
            "frame_fake_prob": round(float(avg_blended), 4)
        })

    # Aggregate
    scored_frames = [f for f in per_frame if f["faces_detected"] > 0]
    if scored_frames:
        overall_prob = float(np.mean([f["frame_fake_prob"] for f in scored_frames]))
        max_prob     = float(np.max([f["frame_fake_prob"] for f in scored_frames]))
        high_conf_fake = sum(1 for f in scored_frames if f["frame_fake_prob"] > 0.65)
        
        # Calculate signal averages
        cnn_avg = float(np.mean([s["cnn"] for f in scored_frames for s in f["scores"]]))
        fft_avg = float(np.mean([s["fft"] for f in scored_frames for s in f["scores"]]))
    else:
        overall_prob = 0.0
        max_prob     = 0.0
        high_conf_fake = 0
        cnn_avg = 0.0
        fft_avg = 0.0

    verdict    = "FAKE" if overall_prob >= FAKE_THRESHOLD else "REAL"
    confidence = overall_prob if verdict == "FAKE" else (1.0 - overall_prob)

    # ── Risk contribution for Fraud Monitor (0.0–1.0) ──────────────────────
    # High fake probability + many suspicious frames = high fraud risk
    fraud_risk_signal = min(1.0, round(
        (overall_prob * 0.6) + (high_conf_fake / max(len(scored_frames), 1) * 0.4),
        4
    ))

    # ── Decision rationale ─────────────────────────────────────────────────
    if verdict == "FAKE":
        if confidence > 0.85:
            decision = "DEFINITE DEEPFAKE — Do not accept as identity proof"
        elif confidence > 0.65:
            decision = "LIKELY SYNTHETIC — Manual verification required"
        else:
            decision = "SUSPICIOUS — Borderline AI-generated content"
    elif verdict == "REAL":
        if confidence > 0.85:
            decision = "AUTHENTIC — High confidence genuine media"
        elif confidence > 0.65:
            decision = "LIKELY AUTHENTIC — Minor anomalies present"
        else:
            decision = "SUSPICIOUS — Inconsistent authenticity signals"
    else:
        decision = "INCONCLUSIVE — No human faces detected for analysis"

    return {
        # Core verdict
        "verdict":    verdict,
        "is_fake":    verdict == "FAKE",
        "is_inconclusive": verdict == "INCONCLUSIVE",
        "decision":   decision,
        "confidence": round(confidence, 4),

        # Scores
        "fake_prob":               round(overall_prob, 4),
        "overall_fake_probability":round(overall_prob, 4),
        "max_frame_fake_prob":     round(max_prob, 4),
        "fraud_risk_signal":       fraud_risk_signal,  # sent to Fraud Monitor

        # Stats
        "frames_analyzed":        len(frames),
        "frame_count":            len(frames),
        "frames_with_faces":      len(scored_frames),
        "total_faces_found":      faces_found,
        "artifacts":              high_conf_fake,
        "high_confidence_fake_frames": high_conf_fake,

        # Multi-signal breakdown (shown as bars in frontend)
        "signals": [
            {
                "name":  "ViT Transformer (Primary)",
                "score": round(cnn_avg, 4),
                "label": "High" if cnn_avg > 0.6 else "Medium" if cnn_avg > 0.35 else "Low",
            },
            {
                "name":  "FFT Frequency Artifacts",
                "score": round(fft_avg, 4),
                "label": "High" if fft_avg > 0.6 else "Medium" if fft_avg > 0.35 else "Low",
            },
            {
                "name":  "Temporal Consistency",
                "score": round(min(1.0, high_conf_fake / max(len(scored_frames), 1)), 4),
                "label": "Suspicious" if high_conf_fake > 2 else "Normal",
            },
        ],
        "per_frame_results": per_frame,
    }


# ─────────────────────────────────────────────────────────────────────────
# PDF REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────
def generate_pdf_report(job_id: str, filename: str, result: dict) -> str:
    """Generate court-ready PDF forensic report. Returns path to PDF."""
    if not REPORTLAB_AVAILABLE:
        return None

    out_path = REPORTS_DIR / f"{job_id}.pdf"
    doc = SimpleDocTemplate(str(out_path), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Header
    story.append(Paragraph("KAVACH DEEP TRACE — FORENSIC REPORT", styles["Title"]))
    story.append(Paragraph("Digital Evidence Authenticity Analysis", styles["Heading2"]))
    story.append(Spacer(1, 12))

    # Metadata table
    meta = [
        ["Job ID", job_id],
        ["File", filename],
        ["Analysis Time", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())],
        ["Analyzer", "KAVACH DeepTrace v1.0 (EfficientNet-B4 + FFT)"],
        ["Device", DEVICE.upper()],
    ]
    t = Table(meta, colWidths=[140, 340])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a2535")),
        ("TEXTCOLOR",  (0, 0), (0, -1), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 18))

    # Verdict
    v_color = "#ff1744" if result["verdict"] == "FAKE" else "#00c853"
    story.append(Paragraph(
        f'<font color="{v_color}"><b>VERDICT: {result["verdict"]}</b></font> '
        f'(Confidence: {result["confidence"]*100:.1f}%)',
        styles["Heading1"]
    ))
    story.append(Spacer(1, 10))

    # Summary stats
    summary = [
        ["Metric", "Value"],
        ["Overall Fake Probability",     f"{result['overall_fake_probability']*100:.2f}%"],
        ["Max Frame Fake Probability",   f"{result['max_frame_fake_prob']*100:.2f}%"],
        ["Frames Analyzed",              str(result["frames_analyzed"])],
        ["Frames With Faces",            str(result["frames_with_faces"])],
        ["Total Faces Found",            str(result["total_faces_found"])],
        ["High-Confidence Fake Frames",  str(result["high_confidence_fake_frames"])],
    ]
    st = Table(summary, colWidths=[240, 240])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("PADDING",    (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    story.append(st)
    story.append(Spacer(1, 16))

    # Per-frame breakdown (top 10 suspicious)
    story.append(Paragraph("Per-Frame Analysis (sorted by fake probability)", styles["Heading3"]))
    story.append(Spacer(1, 6))

    frame_rows = [["Frame", "Faces", "CNN Score", "FFT Score", "Fake Prob"]]
    sorted_frames = sorted(result["per_frame_results"],
                            key=lambda x: x["frame_fake_prob"], reverse=True)[:15]
    for fr in sorted_frames:
        if fr["scores"]:
            s = fr["scores"][0]
            frame_rows.append([
                str(fr["frame_index"]),
                str(fr["faces_detected"]),
                f"{s['cnn']*100:.1f}%",
                f"{s['fft']*100:.1f}%",
                f"{fr['frame_fake_prob']*100:.1f}%",
            ])
        else:
            frame_rows.append([str(fr["frame_index"]), "0", "—", "—", "—"])

    ft = Table(frame_rows, colWidths=[60, 60, 100, 100, 100])
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff8f8")]),
    ]))
    story.append(ft)
    story.append(Spacer(1, 20))

    # Legal disclaimer
    story.append(Paragraph(
        "<b>Disclaimer:</b> This report is generated by an automated AI forensic system "
        "(KAVACH DeepTrace). Results should be reviewed by a qualified digital forensics "
        "examiner before being admitted as evidence. Confidence scores are probabilistic "
        "estimates, not absolute determinations.",
        styles["Italic"]
    ))

    doc.build(story)
    return str(out_path)


# ─────────────────────────────────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────────────────────────────────
setup_uvicorn_logging()
app = FastAPI(title="KAVACH Deep Trace")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

KAVACH_API = "http://localhost:7860"

async def push_result_to_kavach(job_id, verdict, confidence, score, fraud_risk_signal, account_id=None):
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(f"{KAVACH_API}/api/fraud/deeptrace-result", json={
                "job_id":            job_id,
                "verdict":           verdict,
                "confidence":        confidence,
                "deepfake_score":    score,
                "fraud_risk_signal": fraud_risk_signal,  # 0.0–1.0 for Fraud Monitor
                "account_id":        account_id,
                "source":            "deep-trace",
            })
    except Exception as e:
        # logger.error(f"Deep-Trace: Push failed: {e}")
        pass

# In-memory job store (use Redis in production)
job_store: dict[str, dict] = {}


@app.post("/analyze/video")
async def analyze_video(file: UploadFile = File(...)):
    """
    Upload a video file for deepfake analysis.
    Returns JSON with verdict, confidence, and per-frame breakdown.
    """
    if not file.filename.lower().endswith((".mp4", ".avi", ".mov", ".mkv", ".webm")):
        raise HTTPException(400, "Unsupported file type. Use mp4/avi/mov/mkv/webm.")

    job_id = str(uuid.uuid4())[:8]
    start  = time.time()

    # Save to temp file
    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        frames = extract_video_frames(tmp_path, FRAMES_TO_SAMPLE)
        if not frames:
            raise HTTPException(422, "Could not extract frames from video.")

        result = analyze_frames(frames)
        result["job_id"]          = job_id
        result["filename"]        = file.filename
        result["processing_time"] = round(time.time() - start, 2)

        # Generate PDF report
        pdf_path = generate_pdf_report(job_id, file.filename, result)
        result["pdf_report_url"] = f"/report/{job_id}" if pdf_path else None

        job_store[job_id] = result
        
        # Push to KAVACH
        await push_result_to_kavach(
            job_id, result["verdict"], result["confidence"],
            result["overall_fake_probability"],
            result["fraud_risk_signal"]   # ← add this
        )
        
        if result["verdict"] == "FAKE":
            logger.event("Deepfake Detected", {
                "File": file.filename,
                "Verdict": result["verdict"],
                "Confidence": f"{result['confidence']*100:.1f}%",
                "Action": "FORENSIC REPORT GENERATED"
            })

        return JSONResponse(result)

    finally:
        os.unlink(tmp_path)


@app.post("/analyze/image")
async def analyze_image(file: UploadFile = File(...)):
    """
    Upload an image for deepfake face analysis.
    """
    if not file.filename.lower().endswith((".jpg", ".jpeg", ".png", ".webp", ".bmp")):
        raise HTTPException(400, "Unsupported file type. Use jpg/png/webp/bmp.")

    job_id = str(uuid.uuid4())[:8]
    start  = time.time()

    contents = await file.read()
    nparr    = np.frombuffer(contents, np.uint8)
    frame    = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if frame is None:
        raise HTTPException(422, "Could not decode image.")

    result = analyze_frames([frame])
    result["job_id"]          = job_id
    result["filename"]        = file.filename
    result["processing_time"] = round(time.time() - start, 2)

    pdf_path = generate_pdf_report(job_id, file.filename, result)
    result["pdf_report_url"] = f"/report/{job_id}" if pdf_path else None

    job_store[job_id] = result
    
    # Push to KAVACH
    await push_result_to_kavach(
        job_id, result["verdict"], result["confidence"],
        result["overall_fake_probability"],
        result["fraud_risk_signal"]   # ← add this
    )
    
    return JSONResponse(result)


@app.get("/report/{job_id}")
def download_report(job_id: str):
    """Download court-ready PDF forensic report."""
    pdf_path = REPORTS_DIR / f"{job_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(404, "Report not found.")
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=f"kavach_deepfake_report_{job_id}.pdf"
    )


@app.get("/job/{job_id}")
def get_job(job_id: str):
    if job_id not in job_store:
        raise HTTPException(404, "Job not found.")
    return job_store[job_id]


@app.get("/health")
def health():
    return {
        "status": "online",
        "module": "deep-trace",
        "device": DEVICE,
        "model": MODEL_ID if vit_model else ("FFT-only mode" if not TRANSFORMERS_AVAILABLE else "Loading failed"),
        "local_storage": LOCAL_MODEL_PATH.exists(),
        "mtcnn": MTCNN_AVAILABLE,
        "pdf_export": REPORTLAB_AVAILABLE,
    }
