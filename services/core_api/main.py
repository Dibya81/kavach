"""
services/core-api/main.py
Minimal static file server for the frontend.
The real API lives in ai-modules/fir_warden/main.py on port 8000.
This file serves frontend/index.html at http://localhost:9000
so you can open the dashboard without a separate web server.

Run: uvicorn services.core-api.main:app --port 9000
  OR just open frontend/index.html directly in a browser — both work.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pathlib import Path

app = FastAPI(title="KAVACH Frontend Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent.parent / "frontend"

@app.get("/health")
def health():
    return {"status": "ok", "service": "frontend-server", "port": 9000}

@app.get("/api/status")
def status():
    """Quick status check showing all module ports."""
    return {
        "modules": {
            "crowd_sentinel": "http://localhost:9001",
            "deep_trace":     "http://localhost:9002",
            "fir_warden":     "http://localhost:8000",
            "net_watch":      "http://localhost:8000",
            "doc_guard":      "http://localhost:8000",
        },
        "frontend": "http://localhost:9000",
        "note": "Open frontend/index.html directly — no server needed for demo",
    }

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    @app.get("/")
    def no_frontend():
        return JSONResponse({"error": f"Frontend not found at {FRONTEND_DIR}"}, status_code=404)
