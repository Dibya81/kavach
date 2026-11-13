# KAVACH — Advanced AI Police Security & Banking Fraud Detection Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688.svg)](https://fastapi.tiangolo.com/)
[![YOLO: v10%20%2F%2011n](https://img.shields.io/badge/YOLO-v10s%20%7C%2011n-orange.svg)](https://docs.ultralytics.com/)
[![Blockchain: Polygon Amoy](https://img.shields.io/badge/Blockchain-Polygon%20Amoy-8247E5.svg)](https://amoy.polygonscan.com/)

> **KAVACH** is an integrated, intelligence-grade cyber-physical security platform engineered to detect, correlate, and automatically respond to banking fraud in real time.

By fusing real-time CCTV edge intelligence, biometric deepfake detection, forensic document verification, network geolocation telemetry, and multi-channel transaction analysis into a unified scoring and automated First Information Report (FIR) generation pipeline, KAVACH bridges the gap between digital fraud prevention and physical law enforcement.

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [System Architecture](#system-architecture)
  - [High-Level Data Flow](#high-level-data-flow)
  - [Fraud Scoring & Fusion Engine](#fraud-scoring--fusion-engine)
- [Core Modules](#core-modules)
  - [1. Crowd Sentinel (CCTV & Edge Surveillance)](#1-crowd-sentinel-cctv--edge-surveillance)
  - [2. Deep-Trace (Identity & Deepfake Verification)](#2-deep-trace-identity--deepfake-verification)
  - [3. Doc-Guard (KYC Document Forensic Verification)](#3-doc-guard-kyc-document-forensic-verification)
  - [4. Net-Watch (Network & Geolocation Intelligence)](#4-net-watch-network--geolocation-intelligence)
  - [5. FIR-Warden (Automated FIR & Incident Management)](#5-fir-warden-automated-fir--incident-management)
  - [6. Blockchain Evidence Registry](#6-blockchain-evidence-registry)
- [Repository Structure](#repository-structure)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
  - [Method 1: Local Virtual Environment](#method-1-local-virtual-environment)
  - [Method 2: Docker Container](#method-2-docker-container)
  - [Method 3: Makefile Commands](#method-3-makefile-commands)
- [Configuration & Environment Variables](#configuration--environment-variables)
- [Usage & Running the Platform](#usage--running-the-platform)
  - [Running the Unified Application](#running-the-unified-application)
  - [Accessing the Frontend Dashboard](#accessing-the-frontend-dashboard)
  - [Default Credentials](#default-credentials)
  - [Running the Sentinel Edge Agent](#running-the-sentinel-edge-agent)
- [API Reference](#api-reference)
  - [Core & Health](#core--health)
  - [FIR & Police Management](#fir--police-management)
  - [Fraud Scoring & Transactions](#fraud-scoring--transactions)
  - [Net-Watch Telemetry](#net-watch-telemetry)
  - [Crowd Sentinel (Proxied)](#crowd-sentinel-proxied)
  - [Deep-Trace (Proxied)](#deep-trace-proxied)
  - [Blockchain Status & Ledger](#blockchain-status--ledger)
- [Contributing Guidelines](#contributing-guidelines)
- [Roadmap & Future Scope](#roadmap--future-scope)
- [License](#license)

---

## Overview

Modern financial fraud is rarely confined to a single channel. Fraud rings coordinate physical ATM skimming, weapon coercion, falsified identity documents, digital impersonation (deepfakes), and high-frequency automated withdrawals simultaneously.

Traditional banking defense systems operate in isolated silos:
- ATM CCTV recordings are analyzed days after an incident.
- Document validation teams review static KYC PDFs without cross-referencing session telemetry.
- Transaction fraud systems lack real-time context of physical threats or geographic anomalies.
- Evidence chains are vulnerable to accidental alteration or insider tampering.

**KAVACH** resolves these vulnerabilities by operating as a **continuous, unified fusion engine**. When a physical or digital vector triggers an anomaly, KAVACH aggregates signals across all intelligence layers, computes an immediate weighted risk score, automatically drafts an evidentiary FIR, hashes the digital evidence onto a cryptographic blockchain ledger, and updates law enforcement dispatch dashboards instantly.

---

## Problem Statement

| Vector | Traditional Vulnerability | KAVACH Solution |
| :--- | :--- | :--- |
| **ATM / Branch Coercion** | CCTV logs silently; no live action taken during physical robbery. | Dual-model YOLO detects weapons (+80 to +90 risk) and triggers automatic incident reports within milliseconds. |
| **KYC Document Tampering** | Subtle text or photo manipulations bypass basic OCR. | SSIM structural difference analysis + OCR text extraction detects altered fonts, numbers, and layout shifts. |
| **Biometric Impersonation** | Video KYC bypassable via real-time deepfakes or face replay. | Deep-Trace evaluates temporal face consistency, texture artifacts, and landmark continuity. |
| **Network & Location Anomalies** | Proxies and VPNs mask illicit offshore logins. | Automatic client IP geolocation, ISP lookup, access velocity tracking, and windowed DDoS/burst detection. |
| **Evidence Tampering** | Incident logs and FIR records stored in editable databases. | SHA-256 evidence hashing anchored directly to EVM smart contracts (Polygon Amoy) for tamper-evident audits. |

---

## System Architecture

### High-Level Data Flow

```text
  +---------------------------------------------------------------------------------+
  |                             Multi-Channel Input Sources                         |
  |  [CCTV / Webcams]      [KYC Documents]       [Video/Selfie KYC]     [IP / Geo Logs]  |
  +--------+--------------------+-----------------------+---------------------+-----+
           |                    |                       |                     |
           v                    v                       v                     v
     Crowd Sentinel         Doc-Guard               Deep-Trace             Net-Watch
     - YOLOv10s objects     - SSIM diffing          - Deepfake model       - IP Geolocation
     - YOLO11n weapons      - OCR extraction        - Artifact analysis    - Velocity track
     - Mask detection       - Baseline hash         - Facial landmarks     - DDoS windowing
           |                    |                       |                     |
           +--------------------+-----------+-----------+---------------------+
                                            |
                                            v
                         +--------------------------------------+
                         |     KAVACH Fraud Scoring Engine      |
                         |   (Weighted Multi-Signal Fusion)     |
                         |  NetWatch (25%) + DocGuard (20%) +   |
                         | DeepTrace (20%) + Sentinel (15%) +   |
                         |          FIR-Warden (20%)            |
                         +------------------+-------------------+
                                            |
                         +------------------+-------------------+
                         | Risk Threshold Evaluation            |
                         |  - Low: 0 - 39    | Medium: 40 - 69  |
                         |  - High: 70 - 84  | Critical: 85-100 |
                         +------------------+-------------------+
                                            |
                    +-----------------------+-----------------------+
                    | (If Score >= 70 or Critical Weapon Detected)   |
                    v                                               v
        +-----------------------+                       +-----------------------+
        |   FIR-Warden Engine   |                       |  Real-Time WebSocket  |
        | - Auto FIR Generation |                       |  - Operator Alerts    |
        | - Evidence Snapshot   |                       |  - Interactive Map    |
        +-----------+-----------+                       +-----------------------+
                    |
                    v
        +-----------------------------------------------+
        |           Evidence Storage & Blockchain       |
        | - Local SQLite / Supabase PostgreSQL Ledger   |
        | - SHA-256 Cryptographic Hash Anchor           |
        | - Polygon Amoy Testnet (EvidenceRegistry.sol) |
        +-----------------------------------------------+
```

### Fraud Scoring & Fusion Engine

The fusion engine (`ai-modules/fir_warden/fraud_scorer.py`) aggregates confidence signals ($0.0 \text{ to } 1.0$) from each specialized subsystem using strict proportional weights:

$$\text{Fraud Score} = \sum (\text{Signal}_i \times \text{Weight}_i)$$

| Intelligence Subsystem | Weight (%) | Primary Monitored Indicators |
| :--- | :---: | :--- |
| **Net-Watch** | **25%** | IP risk, unexpected geo-hops, proxy/VPN usage, access bursts. |
| **Doc-Guard** | **20%** | Structural SSIM degradation, altered OCR fields, hash mismatch. |
| **Deep-Trace** | **20%** | Facial synthetic artifacts, landmark anomalies, spoofed frames. |
| **FIR-Warden** | **20%** | Historical account risk, repeat incident velocity, open FIRs. |
| **Crowd Sentinel** | **15%** | ATM shoulder surfing, loitering, hardware tampering, masking. |

> **Critical Trigger Exception:** Explicit physical threats (such as a detected firearm, pistol, or knife via Sentinel) automatically add $+80$ to $+90$ risk directly, crossing the critical threshold and instantly triggering automated FIR creation and evidence capture.

---

## Core Modules

### 1. Crowd Sentinel (CCTV & Edge Surveillance)
- **Path:** `ai-modules/crowd_sentinel/`
- **Architecture:** Dual-model inference combining standard object recognition (`YOLOv10s`) for persons, mobile devices, and laptops with a specialized custom threat model (`YOLO11n-Threat`) trained for weapons (guns, knives).
- **Face & Mask Classification:** Automatic face cropping with a PyTorch MobileNet classifier to flag concealed identities (balaclavas, ski masks, helmets).
- **Edge Stream:** Real-time video streaming (`/stream`) and low-latency WebSocket alert broadcast (`/ws/alerts`).

### 2. Deep-Trace (Identity & Deepfake Verification)
- **Path:** `ai-modules/deep_trace/`
- **Capabilities:** Frame-by-frame digital artifact inspection for video KYC and profile pictures.
- **Verification Pipeline:** Evaluates color space consistency, blending boundaries, frequency artifacts, and facial landmark stability to yield confidence scores against synthetic media.

### 3. Doc-Guard (KYC Document Forensic Verification)
- **Path:** `ai-modules/doc_guard/`
- **Forensic Comparison:** Analyzes baseline identity records against submitted scans using Structural Similarity Index (`SSIM`) via OpenCV and Scikit-Image.
- **OCR Inspection:** Dual-pass text extraction (`pytesseract`, `pdfminer.six`) with fuzzy matching (`rapidfuzz`) to spot tampered names, dates of birth, or identification numbers.

### 4. Net-Watch (Network & Geolocation Intelligence)
- **Path:** `ai-modules/net_watch/`
- **Automated IP Telemetry:** Automatically resolves client IP addresses to geographic coordinates using external IP intelligence (ipinfo) with local subnet fallbacks.
- **Anomaly Detection:** Tracks access frequency, geographical jump velocity, and burst requests within a 10-second sliding window to mitigate automated attacks and credential stuffing.
- **Frontend Integration:** Feeds interactive Leaflet.js maps with pinpoint marker tracking and historic session logs.

### 5. FIR-Warden (Automated FIR & Incident Management)
- **Path:** `ai-modules/fir_warden/`
- **Automated Filing:** Automatically generates formal First Information Reports when aggregate risk exceeds $\ge 70$, attaching evidentiary image frames and audit timestamps.
- **Investigator Workflow:** Full police review interface allowing authorized personnel to inspect, verify, reject, or annotate cases with complete audit logging.

### 6. Blockchain Evidence Registry
- **Path:** `ai-modules/fir_warden/blockchain.py`
- **Smart Contract:** EVM-compatible `EvidenceRegistry.sol` configured for the **Polygon Amoy Testnet** (Chain ID `80002`).
- **Cryptographic Anchoring:** Calculates SHA-256 hashes of FIR payloads and evidence files, submitting immutable anchor transactions (`anchorFIR`, `anchorDocument`).
- **Resilient Fallback:** When external blockchain RPC endpoints are unreachable or credentials are not supplied, the platform seamlessly defaults to a local deterministic mock engine to ensure uninterrupted local operation.

---

## Repository Structure

```text
kavach/
├── Dockerfile                      # Containerization recipe for Docker/Hugging Face Spaces
├── Makefile                        # Development automation & service runner
├── README.md                       # Comprehensive platform documentation
├── requirements.txt                # Production Python dependencies
├── requirements-render.txt         # Lightweight deployment dependency profile
├── start.sh                        # Production container startup script
│
├── ai-modules/                     # Core AI, detection, and backend services
│   ├── run.py                      # Unified FastAPI launcher (ports Sentinel & DeepTrace)
│   │
│   ├── crowd_sentinel/             # CCTV & Physical threat intelligence
│   │   ├── main.py                 # Sentinel FastAPI service & WebSocket broker
│   │   ├── threat_mapper.py        # Threat vector scoring & rule logic
│   │   ├── media/                  # Sample threat verification frames
│   │   └── models/                 # Model definitions, weights & documentation
│   │       ├── README.md           # Model architecture and edge CLI documentation
│   │       ├── data.yaml           # YOLO dataset configuration
│   │       ├── sentinel.py         # Standalone edge video processor CLI
│   │       └── *.b64 / *.pt        # PyTorch & YOLO weight files
│   │
│   ├── deep_trace/                 # Biometric identity & deepfake verification
│   │   └── main.py                 # Deep-Trace FastAPI analysis service
│   │
│   ├── doc_guard/                  # Document tampering & OCR verification
│   │   ├── diff_utils.py           # SSIM image diffing & visual contour analysis
│   │   ├── doc_guard.py            # Verification logic & baseline database interface
│   │   └── ocr_utils.py            # Tesseract OCR extraction & string normalization
│   │
│   ├── fir_warden/                 # Primary incident management & fusion backend
│   │   ├── blockchain.py           # Web3.py Polygon Amoy smart contract integration
│   │   ├── config.py               # Environment configuration & Contract ABI
│   │   ├── database.py             # Local SQLite backend with Supabase query layer
│   │   ├── fir_warden.py           # Core FIR generation & evidence handling
│   │   ├── fraud_scorer.py         # 5-vector weighted fusion engine
│   │   ├── init_local_db.py        # SQLite schema initialization script
│   │   ├── main.py                 # Main unified API gateway & proxy router
│   │   └── utils.py                # Hashing, formatting, and ISO timestamp utilities
│   │
│   ├── net_watch/                  # Network telemetry & IP intelligence
│   │   ├── fusion.py               # Cross-channel transaction correlation
│   │   └── net_watch.py            # IP resolution, geolocation & sliding window log
│   │
│   └── shared/                     # Shared logging, schemas, and utility modules
│       ├── base_model.py           # Base model abstractions
│       ├── event_schema.py         # Structured event schemas
│       ├── logger.py               # Colorized startup and Uvicorn log formatting
│       └── redis_publisher.py      # Event bus interface
│
├── frontend/                       # Interactive law enforcement & operator dashboard
│   ├── index.html                  # Main portal landing & quick launcher
│   ├── dashboard.html              # Central real-time intelligence dashboard
│   ├── police_dashboard.html       # Official police investigation & verification suite
│   ├── sentinel.html               # Live CCTV surveillance feed & camera monitor
│   ├── deeptrace.html              # Deepfake video/image inspection lab
│   ├── docguard.html               # KYC document verification & diff inspector
│   ├── netwatch.html               # Real-time IP geolocation map (Leaflet.js)
│   ├── fir.html                    # Incident filing & FIR management portal
│   ├── fraud.html                  # Multi-channel transaction monitoring console
│   ├── blockchain.html             # Immutable ledger & evidence verifier
│   ├── css/                        # Responsive cybersecurity-themed CSS stylesheets
│   └── js/                         # Frontend client logic & REST API bindings
│       ├── api.js                  # Standardized fetch wrapper for all backend routes
│       ├── app.js                  # Global auth guard, dynamic endpoint config & WebSockets
│       └── emailjs-alert.js        # Emergency alert dispatch hooks
│
├── services/
│   └── core_api/
│       └── main.py                 # Static dashboard file server (port 9000 fallback)
│
├── supabase/
│   └── schema.sql                  # Production PostgreSQL schema (tables, RLS, indexes)
│
└── scripts/                        # Database seeding & utility tools
```

---

## Technology Stack

| Layer | Technologies | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2 | High-performance asynchronous REST API and WebSocket gateway. |
| **Computer Vision / AI** | Ultralytics YOLOv10s, YOLO11n, PyTorch, Torchvision, TIMM | Real-time object, weapon, and identity concealment detection. |
| **Deepfake Detection** | PyTorch, Transformers, Accelerate, SafeTensors | Image and video frame-by-frame forensic artifact analysis. |
| **Document Forensics** | Tesseract OCR, OpenCV (Headless), Scikit-Image, RapidFuzz | SSIM image comparison, OCR character extraction, and fuzzy diffing. |
| **Database** | SQLite (Local default) & Supabase PostgreSQL (Cloud) | Flexible persistence; zero-config local storage with full cloud schema. |
| **Blockchain** | Web3.py, Polygon Amoy Testnet (Chain ID 80002) | Tamper-proof evidence hashing and smart-contract verification. |
| **Frontend** | Vanilla JavaScript (ES6+), HTML5, CSS3, Leaflet.js, Lucide | Lightweight, zero-build dashboard operational across any modern browser. |
| **Containerization** | Docker, Debian Slim | Reproducible production deployments on container runtimes. |

---

## Prerequisites

Before setting up KAVACH, ensure your host environment meets the following requirements:

1. **Python 3.10 or higher**:
   ```bash
   python --version
   ```
2. **Git**:
   ```bash
   git --version
   ```
3. **Tesseract OCR** (Required for Doc-Guard OCR):
   - **Ubuntu/Debian:** `sudo apt-get install -y tesseract-ocr libtesseract-dev`
   - **macOS:** `brew install tesseract`
   - **Windows:** Download the official installer from [UB-Mannheim/tesseract](https://github.com/UB-Mannheim/tesseract/wiki) and add the installation folder to your system `PATH`.
4. **OpenCV System Dependencies** (Linux only):
   ```bash
   sudo apt-get install -y libgl1 libglib2.0-0
   ```

---

## Installation & Setup

### Method 1: Local Virtual Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Dibya81/kavach.git
   cd kavach
   ```

2. **Create and activate a virtual environment:**
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - **Windows (PowerShell):**
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```

3. **Install dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Initialize the local SQLite database:**
   ```bash
   python ai-modules/fir_warden/init_local_db.py
   ```

---

### Method 2: Docker Container

KAVACH includes a production-ready `Dockerfile` that packages OpenCV, Tesseract, and all dependencies.

1. **Build the container image:**
   ```bash
   docker build -t kavach:latest .
   ```

2. **Run the container:**
   ```bash
   docker run -d -p 7860:7860 --name kavach-app kavach:latest
   ```

3. Open your browser and navigate to `http://localhost:7860`.

---

### Method 3: Makefile Commands

If you are developing on a Unix-like environment with `make` available:

| Command | Action |
| :--- | :--- |
| `make install` | Creates `venv` and installs `requirements.txt`. |
| `make kavach` | Launches the complete unified platform via `ai-modules/run.py`. |
| `make dev-kavach` | Launches the platform with live reload enabled. |
| `make dev-sentinel`| Runs Crowd Sentinel as an isolated microservice on port 9001. |
| `make dev-trace` | Runs Deep-Trace as an isolated microservice on port 9002. |
| `make dev-core` | Runs the static frontend server on port 9000. |

---

## Configuration & Environment Variables

KAVACH is designed to run **out of the box** in local demonstration mode without external accounts. For full cloud and blockchain connectivity, create a `.env` file in the project root:

```ini
# ============================================================
# KAVACH System Configuration
# ============================================================

# Network & Server
PORT=7860
PYTHONPATH=.

# Blockchain (Polygon Amoy Testnet)
RPC_URL=https://rpc-amoy.polygon.technology/
CONTRACT_ADDRESS=0x0000000000000000000000000000000000000000
PRIVATE_KEY=0000000000000000000000000000000000000000000000000000000000000000

# Cloud Database (Supabase PostgreSQL - Optional)
# If omitted, KAVACH automatically uses local SQLite (kavach_local.db)
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your-supabase-service-key

# IP Telemetry (Optional)
# If omitted, Net-Watch gracefully uses localhost geolocation fallbacks
IPINFO_TOKEN=your_ipinfo_api_token
```

### Environment Variable Reference

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `PORT` | No | `7860` | Server listening port for the unified backend. |
| `PYTHONPATH` | No | `.` / `/app` | Python module lookup path. |
| `RPC_URL` | No | `https://rpc-amoy.polygon.technology/` | EVM RPC provider endpoint. |
| `CONTRACT_ADDRESS` | Conditional | *(empty)* | Deployed `EvidenceRegistry` contract address. |
| `PRIVATE_KEY` | Conditional | *(empty)* | Operator wallet private key for signing evidence transactions. |
| `SUPABASE_URL` | No | *(empty)* | Supabase project URL for cloud persistence. |
| `SUPABASE_KEY` | No | *(empty)* | Supabase service API key. |
| `IPINFO_TOKEN` | No | `""` | Token for external IP geolocation queries. |

> **Graceful Degradation:** When `CONTRACT_ADDRESS` or `PRIVATE_KEY` are not provided, KAVACH logs `Blockchain: Not connected (Mock Mode)` and continues operating normally, simulating transaction hashes deterministically.

---

## Usage & Running the Platform

### Running the Unified Application

The unified launcher starts the primary FIR-Warden gateway and mounts Crowd Sentinel and Deep-Trace under internal proxy routes, serving all API endpoints and dashboards:

```bash
python ai-modules/run.py --port 7860
```

### Accessing the Frontend Dashboard

1. If running the backend, navigate to:
   - **Unified Portal:** `http://localhost:7860` or `http://localhost:7860/frontend/`
   - **Alternative Static Server:** Run `python -m http.server 3000 --directory frontend` and visit `http://localhost:3000`
2. You can also open `frontend/index.html` directly in any modern web browser without a web server; `frontend/js/app.js` automatically routes API calls to the local or cloud backend.

### Default Credentials

For demonstrations and operator access:
- **Badge ID / Username:** `admin`
- **Password:** `admin`
- **Role:** `ADMINISTRATOR` (Grants full verification and auditing rights)

---

### Running the Sentinel Edge Agent

To run the surveillance agent directly on an ATM edge terminal or local workstation using an integrated webcam or video feed:

```bash
# Live webcam feed
python ai-modules/crowd_sentinel/models/sentinel.py --source 0

# Prerecorded CCTV simulation video
python ai-modules/crowd_sentinel/models/sentinel.py --source path/to/cctv_feed.mp4

# Forward alerts to KAVACH unified backend
python ai-modules/crowd_sentinel/models/sentinel.py --source 0 --webhook http://localhost:7860/api/police/detections
```

---

## API Reference

All REST endpoints return JSON responses. If authentication is enabled, pass the session token as a bearer header: `Authorization: Bearer kavach_admin_token`.

### Core & Health

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Unified system health check and Unix epoch timestamp. |
| `GET` | `/api/dashboard/summary` | Aggregated metrics (total FIRs, pending reviews, active alerts). |

### FIR & Police Management

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/fir/report` | Submit and register a new manual or automated FIR. |
| `GET` | `/api/fir` | Retrieve registered FIR incident records. |
| `GET` | `/api/police/stats` | Law enforcement statistics (resolved cases, high-risk flags). |
| `GET` | `/api/police/detections` | Historical physical and digital detection events. |
| `POST` | `/api/police/detections` | Ingest detection records from edge CCTV sentinels. |
| `POST` | `/api/police/verify` | Officer verification action (`VERIFIED`, `REJECTED`, `UNDER_REVIEW`). |
| `GET` | `/api/police/audit/{fir_id}` | Retrieve tamper-proof audit trail for a specific FIR. |

### Fraud Scoring & Transactions

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/fraud/transaction` | Ingest banking transaction and compute multi-channel fraud score. |
| `GET` | `/api/fraud/transactions` | Query recent transactions (supports `flagged=true`, `account_id`, `limit`). |
| `GET` | `/api/fraud/stats` | Global fraud risk statistics and high-severity counts. |
| `POST` | `/api/event` | Ingest generic telemetry event into the fusion queue. |

### Net-Watch Telemetry

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/net-watch/access-log` | Retrieve real-time IP access, ISP, and coordinate records. |
| `GET` | `/api/net-watch/stats` | Network anomaly statistics, burst flags, and unique client counts. |
| `GET` | `/api/net-watch/capture` | Capture and log the current requesting client's IP and coordinates. |

### Crowd Sentinel (Proxied)

Mounted at `/api/proxy/sentinel` on the unified host:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/proxy/sentinel/analyze_frame` | Submit single image frame for weapon and object inference. |
| `GET` | `/api/proxy/sentinel/risk` | Current risk level of live camera feed. |
| `GET` | `/api/proxy/sentinel/detections` | Latest bounding box detection list. |
| `GET` | `/api/proxy/sentinel/stream` | Multipart MJPEG surveillance video stream. |
| `WS` | `/api/ws/alerts` | Real-time WebSocket connection for live detection alerts. |

### Deep-Trace (Proxied)

Mounted at `/api/proxy/deeptrace` on the unified host:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/proxy/deeptrace/analyze/image` | Upload image for biometric synthetic media analysis. |
| `POST` | `/api/proxy/deeptrace/analyze/video` | Upload video file for frame-by-frame deepfake evaluation. |
| `GET` | `/api/proxy/deeptrace/job/{job_id}` | Query status of an asynchronous video analysis job. |
| `GET` | `/api/proxy/deeptrace/report/{job_id}` | Retrieve completed forensic artifact report. |

### Blockchain Status & Ledger

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/chain/status` | Current Web3 provider connectivity and network details. |
| `GET` | `/api/blockchain` | Query anchored evidence records, block numbers, and transaction IDs. |

---

## Contributing Guidelines

Contributions to KAVACH are welcome. To maintain code quality and security standards, follow these guidelines:

1. **Fork & Branch:** Create a feature branch with a descriptive name:
   ```bash
   git checkout -b feature/improved-weapon-heuristics
   ```
2. **Follow Existing Style:**
   - Adhere to PEP 8 standards for Python code.
   - Use meaningful variable names and structured error handling.
   - Do not commit sensitive credentials, keys, or personal access tokens.
3. **Documentation:**
   - When modifying or adding API routes or configuration flags, update `README.md` and inline docstrings accordingly.
4. **Commit Messages:** Use conventional commit formatting:
   - `docs: update setup and architecture instructions`
   - `feat: add burst window configuration to net-watch`
   - `fix: resolve SQLite foreign key constraint on FIR status update`
5. **Pull Requests:** Open a PR against the `main` branch with a clear description of changes and test results.

---

## Roadmap & Future Scope

- [ ] **Edge Hardware Optimization:** Convert custom YOLO and MobileNet models to ONNX and TensorRT formats for enhanced FPS on NVIDIA Jetson edge devices.
- [ ] **Cross-Camera Re-Identification:** Multi-camera tracking to follow identified persons of interest across banking branch networks.
- [ ] **Decentralized Storage:** Direct IPFS / Filecoin anchoring for larger video evidence files alongside blockchain transaction hashes.
- [ ] **Law Enforcement CAD Relay:** Standardized integration with police Computer-Aided Dispatch (CAD) protocols for automated emergency response.
- [ ] **Mobile Field Client:** Lightweight Flutter or React Native interface for field officers responding to active branch alerts.

---

## License

This project is licensed under the [MIT License](LICENSE).
