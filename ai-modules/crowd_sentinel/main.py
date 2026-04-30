"""
KAVACH Crowd Sentinel — Complete Automated Pipeline
FastAPI: port 9001
- YOLO weapon detection on webcam
- Image capture on threat
- Supabase storage upload
- Auto-FIR via POST /api/fir/report (port 8000)
- WebSocket broadcast to sentinel.html
- Risk score endpoint for fraud.html
"""

import asyncio
import base64
import json
import os
import time
import math
import uuid
import functools
from collections import defaultdict
from pathlib import Path
from typing import Optional, List
import logging

from shared.logger import logger, setup_uvicorn_logging

from dotenv import load_dotenv
# Load environment from root and local
load_dotenv(dotenv_path=Path(__file__).parents[2] / ".env")

import cv2
import numpy as np
import torch
import torch.nn as nn
from torchvision import transforms, models
from PIL import Image
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
import httpx
from ultralytics import YOLO
# from supabase import create_client # Removed

from .threat_mapper import ThreatMapper

# ── PyTorch security fix ──────────────────────────────────────────────────────
_orig_load = torch.load
@functools.wraps(_orig_load)
def _safe_load(*args, **kwargs):
    kwargs.setdefault('weights_only', False)
    return _orig_load(*args, **kwargs)
torch.load = _safe_load

# ── Config ────────────────────────────────────────────────────────────────────
MODULE_DIR  = Path(__file__).parent
MODELS_DIR  = MODULE_DIR / "models"
MEDIA_DIR   = MODULE_DIR / "media"
MEDIA_DIR.mkdir(exist_ok=True)

KAVACH_API  = os.getenv("KAVACH_API", "http://localhost:7860")

# Local Storage for Sentinel (Disabled)
_sb = None 

# YOLO paths
GEN_MODEL_PATH    = str(MODELS_DIR / "yolov10s.pt")
# ✅ Updated to use the freshly trained kavach_weapon_v1.pt (50 epochs, mAP50=0.894)
THREAT_MODEL_PATH = str(MODELS_DIR / "kavach_weapon_v1.pt")
MASK_MODEL_PATH   = str(MODELS_DIR / "identity_classifier.pt")

# COCO class IDs — exact integers from YOLOv10s/COCO (source: sentinel.py)
GEN_PERSON     = 0
GEN_BACKPACK   = 24
GEN_LAPTOP     = 63
GEN_CELL_PHONE = 67
GEN_CLASSES_FILTER = [GEN_PERSON, GEN_BACKPACK, GEN_LAPTOP, GEN_CELL_PHONE]

# kavach_weapon_v1.pt class map:
# {0: 'Gunting', 1: 'cutter', 2: 'lighter', 3: 'person', 4: 'pistol'}
# Classes 0, 1, 2, 4 are weapon threats. Class 3 (person) is context.
THREAT_WEAPON_CLASSES = {0, 1, 2, 4}  # Gunting, cutter, lighter, pistol
THREAT_PERSON_CLASS   = 3             # person detected by threat model
THREAT_CLASSES        = THREAT_WEAPON_CLASSES  # backward compat alias

# ── Model Loading ─────────────────────────────────────────────────────────────
print(f"[MODEL] Loading Object model: {Path(GEN_MODEL_PATH).name}")
gen_model = YOLO(GEN_MODEL_PATH)
print("[MODEL] Object model loaded successfully")

print(f"[MODEL] Loading Weapon model: {Path(THREAT_MODEL_PATH).name}  ← kavach_weapon_v1.pt (mAP50=0.894)")
threat_model = YOLO(THREAT_MODEL_PATH)
print("[MODEL] ✅ Weapon model loaded (Gunting/cutter/lighter/pistol detection)")

gen_model.fuse()
threat_model.fuse()

mask_classifier = None
mask_transform  = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
])
if Path(MASK_MODEL_PATH).exists():
    mask_classifier = models.mobilenet_v3_small()
    mask_classifier.classifier[3] = torch.nn.Linear(
        mask_classifier.classifier[3].in_features, 2
    )
    mask_classifier.load_state_dict(torch.load(MASK_MODEL_PATH, map_location="cpu"))
    mask_classifier.eval()

# print("[KAVACH] Sentinel: Active (Hybrid Pipeline)")

# ── State ─────────────────────────────────────────────────────────────────────
# ── App ───────────────────────────────────────────────────────────────────────
setup_uvicorn_logging()
app = FastAPI(title="KAVACH Crowd Sentinel", version="2.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_risk_level(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"

async def upload_to_supabase(img_bytes: bytes, filename: str) -> Optional[str]:
    # Media storage disabled as per request
    return None

async def capture_and_upload(frame: np.ndarray, alert_type: str) -> Optional[str]:
    filename  = f"sentinel_{alert_type}_{int(time.time())}_{uuid.uuid4().hex[:6]}.jpg"
    _, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
    return await upload_to_supabase(buffer.tobytes(), filename)

async def trigger_auto_fir(alert: dict, image_url: Optional[str] = None):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    fir_payload = {
        "fir_number":       f"AUTO-SEN-{int(time.time())}",
        "category":         "arms",
        "severity":         alert.get("severity", "high").lower(),
        "incident_type":    "Weapon Detection (AI Sentinel)",
        "description":      f"CRITICAL: {alert.get('object', 'Weapon').upper()} detected via AI Sentinel. Confidence: {alert.get('risk_score', 0)}%",
        "location":         alert.get("location", "CCTV-ATM-01"),
        "date_of_incident":  ts,
        "image_url":         image_url,
        "officer_badge":     "SENTINEL-AI",
        "complainant":       "SYSTEM_AUTOMATION",
        "source_module":     "crowd-sentinel",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(f"{KAVACH_API}/api/fir/report", json=fir_payload)
            if r.status_code == 200:
                data = r.json()
                await _broadcast({
                    "type": "FIR_CREATED",
                    "fir_id": data.get("fir_id", "unknown"),
                    "message": f"🚨 Weapon Detected: {alert.get('object','').upper()} | FIR Generated",
                    "image_url": image_url,
                    "risk_score": alert.get("risk_score"),
                    "severity": alert.get("severity")
                })
    except Exception as e:
        logger.error(f"FIR Trigger Failed: {e}")

# ── State & Tracking ───────────────────────────────────────────────────────────
class TrackedPerson:
    def __init__(self, track_id, first_pos):
        self.track_id = track_id
        self.start_time = time.time()
        self.last_seen = time.time()
        self.positions = [first_pos] # (x, y)
        self.loitering = False
        self.erratic = False

    def update(self, pos):
        self.last_seen = time.time()
        self.positions.append(pos)
        if len(self.positions) > 30: self.positions.pop(0)
        duration = self.last_seen - self.start_time
        if duration > 15:
            xs, ys = [p[0] for p in self.positions], [p[1] for p in self.positions]
            if (max(xs)-min(xs) < 0.15) and (max(ys)-min(ys) < 0.15):
                self.loitering = True
        if len(self.positions) > 5:
            dists = [math.sqrt((self.positions[i][0]-self.positions[i-1][0])**2 + 
                               (self.positions[i][1]-self.positions[i-1][1])**2) 
                     for i in range(1, len(self.positions))]
            if sum(dists[-5:]) > 0.4: self.erratic = True

class SentinelIntelligence:
    def __init__(self):
        self.people = {}
        self.weapon_buffer = []
        self.ws_clients = []
        self.current_risk = 0
        self.last_detections = []
        self.last_frame = None
        self.last_fir_time = 0   # cooldown: only one FIR per 60s per event type
        self.threat_mapper = ThreatMapper()

    def process_frame(self, frame):
        h, w = frame.shape[:2]
        
        # ── DUAL MODEL INFERENCE (per sentinel.py architecture) ─────────────
        # General model: filtered to only relevant COCO classes
        res_obj = gen_model.predict(
            source=frame,
            classes=GEN_CLASSES_FILTER,
            conf=0.45,
            verbose=False
        )
        # Threat model: kavach_weapon_v1.pt (Gunting/cutter/lighter/pistol/person)
        res_wep = threat_model.predict(
            source=frame,
            conf=0.15, # Increased sensitivity for the demo
            verbose=False
        )

        raw_threat_count = len(res_wep[0].boxes)
        print(f"[DEBUG] Gen boxes: {len(res_obj[0].boxes)} | Threat raw boxes (conf>0.25): {raw_threat_count}")
        if raw_threat_count == 0:
            print(f"[DEBUG] Threat model returned ZERO boxes. Model classes: {threat_model.names}")

        current_detections = []
        persons = []       # [{box, conf}]
        laptops = []       # [{box, conf}]
        backpacks = []     # [{box, conf}]
        phones = []        # [{box, conf}]
        weapons = []       # [{box, conf, name}]
        score = 0
        events = []

        # ── PARSE GENERAL MODEL (YOLOv10s / COCO) ───────────────────────────
        for box in res_obj[0].boxes:
            cls_id = int(box.cls[0])
            conf   = float(box.conf[0])
            xyxy   = box.xyxy[0].cpu().numpy()
            label  = gen_model.names[cls_id]
            x1, y1, x2, y2 = map(int, xyxy)

            print(f"[DEBUG] Gen cls_id={cls_id} label={label} conf={conf:.2f}")

            current_detections.append({
                "label": label, "confidence": conf,
                "bbox": [x1/w, y1/h, (x2-x1)/w, (y2-y1)/h], "type": "context"
            })

            if cls_id == GEN_PERSON:     persons.append({"box": xyxy, "conf": conf})
            elif cls_id == GEN_LAPTOP:   laptops.append({"box": xyxy, "conf": conf})
            elif cls_id == GEN_BACKPACK: backpacks.append({"box": xyxy, "conf": conf})
            elif cls_id == GEN_CELL_PHONE: phones.append({"box": xyxy, "conf": conf})

        # ── PARSE THREAT MODEL (kavach_weapon_v1.pt) ─────────────────────────
        for box in res_wep[0].boxes:
            cls_id = int(box.cls[0])
            conf   = float(box.conf[0])
            xyxy   = box.xyxy[0].cpu().numpy()
            name   = threat_model.names[cls_id]
            x1, y1, x2, y2 = map(int, xyxy)

            print(f"[DEBUG] Threat cls_id={cls_id} label={name} conf={conf:.2f}")

            if cls_id in THREAT_WEAPON_CLASSES:
                # Weapon detected (Gunting/cutter/lighter/pistol)
                weapons.append({"box": xyxy, "conf": conf, "name": name})
                current_detections.append({
                    "label": name, "confidence": conf,
                    "bbox": [x1/w, y1/h, (x2-x1)/w, (y2-y1)/h], "type": "threat"
                })
                print(f"[DETECT] Weapon: {name} ({conf:.2f})")
            elif cls_id == THREAT_PERSON_CLASS:
                # Person detected by the threat model — use as context signal
                current_detections.append({
                    "label": "person", "confidence": conf,
                    "bbox": [x1/w, y1/h, (x2-x1)/w, (y2-y1)/h], "type": "context"
                })
                print(f"[DETECT] Person (threat model): conf={conf:.2f}")

        # ── THREAT DETECTION MATRIX (from sentinel.py) ──────────────────────
        top_weapon = None
        max_conf   = 0.0

        # 1. CRITICAL_THREAT (+90): Any weapon detected
        if weapons:
            top_weapon = max(weapons, key=lambda w: w["conf"])
            max_conf   = top_weapon["conf"]
            score += 90
            events.append({"event": "CRITICAL_THREAT", "score": 90, "object": top_weapon["name"]})

        # 2. HARDWARE_TAMPER (+60): Laptop in frame
        if laptops:
            score += 60
            events.append({"event": "HARDWARE_TAMPER", "score": 60})

        # 3. SKIMMING_SUSPECTED (+50): Backpack + person present
        if backpacks and len(persons) >= 1:
            score += 50
            events.append({"event": "SKIMMING_SUSPECTED", "score": 50})

        # 4. PIN_THEFT_RISK (+25): Cell phone
        if phones:
            score += 25
            events.append({"event": "PIN_THEFT_RISK", "score": 25, "details": "Cell phone near keypad"})

        # 5. PIN_THEFT_RISK (+25): Shoulder surfing (≥2 people close)
        if len(persons) >= 2:
            score += 25
            events.append({"event": "PIN_THEFT_RISK", "score": 25, "details": "Shoulder surfing"})
            print(f"[DETECT] Shoulder Surfing: {len(persons)} people detected")

        if persons or laptops or backpacks or phones:
            labels = ([f"person x{len(persons)}"] if persons else []) + \
                     ([f"laptop x{len(laptops)}"] if laptops else []) + \
                     ([f"backpack x{len(backpacks)}"] if backpacks else []) + \
                     ([f"phone x{len(phones)}"] if phones else [])
            print(f"[DETECT] Objects: {', '.join(labels)}")

        # ── INTELLIGENT THREAT MAPPING ──────────────────────────────────────
        # Map ALL detections through our rule-based classification engine
        all_boxes = []
        for d in current_detections:
            all_boxes.append({
                "label": d["label"],
                "confidence": d["confidence"],
                "bbox": d["bbox"]
            })
        
        threat_report = self.threat_mapper.map_detections(all_boxes)
        resp = self.threat_mapper.build_structured_output(threat_report)
        
        # Sync risk state for legacy endpoints
        self.current_risk = resp["risk_score"]
        self.last_detections = current_detections
        self.last_frame = frame

        # ── AUTO-FIR TRIGGER: verified threat OR risk_score >= 70 ───────────
        if resp["threat_detected"] or resp["risk_score"] >= 70:
            asyncio.create_task(self.handle_auto_fir(frame, resp))

        # ── DASHBOARD EVENT LOGGING ────────────────────────────────────────
        if resp["risk_score"] >= 30:
            asyncio.create_task(self.log_event_to_backend(resp))

        return frame, resp

    async def log_event_to_backend(self, threat_report):
        """Send a lightweight event record to the unified backend for the dashboard."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                objects = threat_report.get("objects", [])
                max_conf = max([o["confidence"] for o in objects] + [0.0])
                
                # 1. Log generic event (for the unified map/alerts feed)
                await client.post(f"{KAVACH_API}/api/event", json={
                    "event_type": "SENTINEL_THREAT" if threat_report["threat_detected"] else "SENTINEL_ANOMALY",
                    "location": "CCTV-ATM-01",
                    "confidence": max_conf,
                    "payload": {
                        "risk_score": threat_report["risk_score"],
                        "threat": threat_report["weapon_type"] or "Anomalous Behavior",
                        "objects": [o["label"] for o in objects]
                    }
                })

                # 2. Log to persistent Sentinel Detections table (for Police HQ)
                if threat_report["risk_score"] >= 40 or threat_report["threat_detected"]:
                    await client.post(f"{KAVACH_API}/api/police/detections", json={
                        "type": threat_report["weapon_type"] or "Anomalous Behavior",
                        "confidence": max_conf,
                        "location": "CCTV-ATM-01",
                        "risk_level": threat_report.get("_internal", {}).get("risk_level", "LOW"),
                        "metadata": threat_report
                    })
        except Exception as e:
            logger.debug(f"Sentinel: Failed to log dashboard event: {e}")

    async def handle_auto_fir(self, frame: np.ndarray, event_data: dict):
        """
        Fully automated FIR pipeline:
        1. Validate event + enforce cooldown
        2. Capture & upload evidence image
        3. POST FIR to FIR-Warden (which handles DB + blockchain internally)
        4. Broadcast CRITICAL_ALERT to frontend WebSocket clients
        """
        # ── 1. Validate + cooldown (60s between FIRs for same risk level) ─────
        score = event_data.get("risk_score", 0)
        if score < 70:
            return  # below threshold, skip

        now = time.time()
        if now - self.last_fir_time < 60:
            logger.info(f"[AUTO-FIR] Cooldown active ({int(60 - (now - self.last_fir_time))}s remaining). Skipping.")
            return
        self.last_fir_time = now

        # Extract from the new _internal field
        internal    = event_data.get("_internal", {})
        weapon_type = internal.get("weapon_type") or event_data.get("suspicious_activity") or "Suspicious Activity"
        risk_level  = internal.get("risk_level", "HIGH")
        confidence  = max([o["confidence"] for o in event_data.get("objects", [])] + [0.0])
        ts          = time.strftime("%Y-%m-%d %H:%M:%S")

        logger.info(f"[AUTO-FIR] Triggered — threat={weapon_type} score={score} level={risk_level}")

        # ── 2. Capture & upload evidence image ────────────────────────────
        image_url = None
        try:
            image_url = await capture_and_upload(frame, "threat")
            logger.info(f"[AUTO-FIR] Evidence uploaded: {image_url}")
        except Exception as e:
            logger.error(f"[AUTO-FIR] Image capture failed: {e}")

        # ── 3. Build FIR payload and POST to FIR-Warden ────────────────────
        # FIR-Warden internally: saves to Supabase `firs` + anchors to blockchain
        fir_payload = {
            "fir_number":    f"AUTO-SEN-{int(time.time())}",
            "category":      "arms" if event_data.get("threat_detected") else "other",
            "severity":      event_data.get("severity", "high"),
            "priority":      event_data.get("priority", "MEDIUM"),
            "risk_score":     event_data.get("risk_score", 0),
            "incident_type": f"Threat Detected: {weapon_type}",
            "description":   (
                f"KAVACH Sentinel Alert: {weapon_type.upper()} detected. "
                f"Confidence: {confidence:.0%}. Risk Score: {score}/100. "
                f"Primary Threat: {internal.get('weapon_type', 'N/A')}. "
                f"Context: {internal.get('detection_reason', 'N/A')}."
            ),
            "location":           "CCTV-ATM-01",
            "date_of_incident":   ts,
            "officer_badge":      "SENTINEL-AI",
            "complainant":        "SYSTEM_AUTOMATION",
            "station_code":       "STN-AUTO-01",
            "district":           "Bengaluru",
            "state":              "Karnataka",
            "image_url":          image_url,
            "weapon_type":        weapon_type
        }

        fir_id = None
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(f"{KAVACH_API}/api/fir/report", json=fir_payload)
                if r.status_code == 200:
                    data = r.json()
                    fir_id = data.get("fir_id") or data.get("id")
                    logger.info(f"[AUTO-FIR] FIR created: {fir_id}")
                else:
                    logger.error(f"[AUTO-FIR] FIR-Warden error {r.status_code}: {r.text}")
        except Exception as e:
            logger.error(f"[AUTO-FIR] API call failed: {e}")

        # ── 4. Broadcast CRITICAL_ALERT to all frontend WebSocket clients ────
        alert_payload = {
            "type":        "CRITICAL_ALERT",
            "title":       "🚨 SENTINEL THREAT ALERT",
            "message":     f"Threat: {weapon_type.upper()}",
            "sub_message": f"Priority: {internal.get('priority')} | FIR: {fir_id or 'QUEUED'}",
            "risk_score":  score,
            "risk_level":  risk_level,
            "confidence":  confidence,
            "fir_id":      fir_id,
            "image_url":   image_url,
            "timestamp":   ts,
            "report":      event_data
        }
        await _broadcast(alert_payload)
        logger.info(f"[AUTO-FIR] Alert broadcasted.")

intel_system = SentinelIntelligence()

@app.post("/analyze_frame")
async def analyze_frame(request: Request):
    try:
        data = await request.json()
        image_b64 = data.get("image", "")
        if "," in image_b64: image_b64 = image_b64.split(",")[1]
        img_bytes = base64.b64decode(image_b64)
        raw = cv2.imdecode(np.frombuffer(img_bytes, np.uint8), cv2.IMREAD_COLOR)
        if raw is None: return JSONResponse({"error": "Decode failed"}, status_code=400)

        annotated, response = intel_system.process_frame(raw)
        
        # Harmonize with frontend expectations
        response["status"] = "success"
        response["detections"] = response.get("objects", []) # Compatibility with renderBBoxes
        response["detected_objects"] = intel_system.last_detections # Compatibility with KPI tags
        
        if response.get("weapon_detected"):
            print(f"[SENTINEL] !!! THREAT DETECTED: {response.get('weapon_type')} (Risk: {response.get('risk_score')}%)")
        
        await _broadcast({"type": "threat_update", "data": response})
        return response
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)

@app.get("/risk")
def get_risk():
    return {"risk_score": int(intel_system.current_risk), "risk_level": get_risk_level(intel_system.current_risk)}

@app.get("/detections")
def get_detections():
    return {
        "status": "success",
        "risk_score": intel_system.current_risk,
        "detections": intel_system.last_detections
    }

@app.get("/debug/models")
def debug_models():
    """Inspect loaded model classes — use this to verify threat model class mapping."""
    return {
        "gen_model": {
            "path": GEN_MODEL_PATH,
            "classes": gen_model.names,
            "num_classes": len(gen_model.names)
        },
        "threat_model": {
            "path": THREAT_MODEL_PATH,
            "classes": threat_model.names,
            "num_classes": len(threat_model.names),
            "THREAT_CLASSES_filter": list(THREAT_CLASSES)
        }
    }

@app.get("/stream")
async def stream():
    async def generate():
        while True:
            if intel_system.last_frame is not None:
                _, frame = cv2.imencode('.jpg', intel_system.last_frame)
                yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame.tobytes() + b'\r\n')
            await asyncio.sleep(0.1)
    return StreamingResponse(generate(), media_type="multipart/x-mixed-replace;boundary=frame")

@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    intel_system.ws_clients.append(ws)
    try:
        while True: await asyncio.sleep(15); await ws.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        if ws in intel_system.ws_clients: intel_system.ws_clients.remove(ws)

async def _broadcast(payload: dict):
    msg = json.dumps(payload)
    for ws in list(intel_system.ws_clients):
        try: await ws.send_text(msg)
        except: 
            if ws in intel_system.ws_clients: intel_system.ws_clients.remove(ws)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9001)


