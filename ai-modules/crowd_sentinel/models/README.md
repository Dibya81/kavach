# KAVACH ATM-Sentinel: Edge Surveillance & Threat Detection

KAVACH ATM-Sentinel is an edge-optimized computer vision surveillance module engineered to detect physical banking fraud, armed robbery, hardware tampering, and suspicious behavioral anomalies at ATMs and bank branches in real time.

Unlike passive surveillance systems that simply record video, Sentinel employs a **Dual-Model YOLO Architecture** coupled with a facial classification head to instantly translate physical anomalies into structured fraud vectors and trigger immediate downstream automated responses.

---

## Key Features

- **Dual-Model Inference Pipeline:**
  - `YOLOv10s`: Detects common objects, persons, cell phones, backpacks, and laptops.
  - Custom `YOLO11n-Threat`: Specialized model trained specifically to detect firearms, handguns, and knives with high precision.
- **Edge Optimized & NMS-Free:** Engineered for smooth inference on edge processors without computationally heavy post-processing Non-Maximum Suppression (NMS).
- **Two-Stage Identity Classifier:** Crops detected face regions and runs a lightweight MobileNet PyTorch classifier to detect concealment gear (balaclavas, helmets, and ski masks).
- **Automated Alert Dispatch:** Dispatches structured JSON alerts via REST webhooks and real-time WebSockets directly into the KAVACH centralized fusion engine.

---

## Threat Detection Matrix

The surveillance engine scores detected vectors against a weighted risk matrix:

| Vector Code | Risk Points | Trigger Condition |
| :--- | :---: | :--- |
| `CRITICAL_THREAT` | **+90** | Firearm, pistol, or knife detected in camera frame. |
| `HARDWARE_TAMPER` | **+60** | Unauthorized laptops, electronic tools, or skimming rigs attached to terminal. |
| `SKIMMING_SUSPECTED` | **+50** | Toolkits, loose backpacks, or foreign hardware placed near card slot/cash dispenser. |
| `IDENTITY_MASKED` | **+30** | Balaclava, motorcycle helmet, or full face cover detected on person. |
| `PIN_THEFT_RISK` | **+25** | Mobile phone positioned over keypad or multiple persons in close proximity (shoulder surfing). |

---

## Directory Contents

- `sentinel.py`: Standalone edge video processor script supporting webcams, video files, and remote streams.
- `data.yaml`: YOLO dataset configuration for custom threat classes.
- `yolo11n_threat_detection.b64`: Base64 encoded custom threat detection model weights.
- `requirements.txt`: Python package requirements for the Sentinel edge pipeline.

---

## Installation & Setup

1. **Navigate to the model directory or project root:**
   ```bash
   cd ai-modules/crowd_sentinel/models
   ```

2. **Install dependencies:**
   Ensure your Python virtual environment is active, then install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify model weights:**
   Ensure model weights (`yolo11n_threat_detection.pt` or base64 equivalent and `yolov10s.pt`) are present in the models directory before starting inference.

---

## Usage Instructions

The `sentinel.py` script can process a live webcam feed, simulated CCTV video file, or forward detection events to the KAVACH core backend.

### 1. Run Live Inference with Local Webcam
```bash
python sentinel.py --source 0
```

### 2. Run Inference on a Recorded Video File
```bash
python sentinel.py --source "path/to/cctv_simulation.mp4"
```

### 3. Forward Alerts to the Central KAVACH Fusion Engine
To automatically post detections into the running KAVACH backend:
```bash
python sentinel.py --source 0 --webhook "http://localhost:7860/api/police/detections"
```

---

## Architecture & Integration Notes

- When running the unified KAVACH platform (`python ai-modules/run.py`), Sentinel's FastAPI server is automatically mounted at `/api/proxy/sentinel`, exposing `/analyze_frame`, `/risk`, `/detections`, and `/stream`.
- WebSocket alerts are broadcasted simultaneously across `/api/ws/alerts` for live visual notification in the frontend dashboard (`frontend/sentinel.html`).
