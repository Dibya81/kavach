.PHONY: install venv \
        sentinel dev-sentinel \
        dev-trace dev-guard dev-core \
        dev-kavach kavach \
        chain-node chain-deploy

# ── Setup ─────────────────────────────────────────────────────────────────────
venv:
	python3 -m venv venv

install:
	[ -d venv ] || python3 -m venv venv
	./venv/bin/pip install -r requirements.txt

# ── ai-modules: crowd-sentinel ────────────────────────────────────────────────
sentinel:
	./venv/bin/uvicorn ai-modules.crowd_sentinel.main:app --host 0.0.0.0 --port 9001

dev-sentinel:
	./venv/bin/uvicorn ai-modules.crowd_sentinel.main:app --host 0.0.0.0 --port 9001 --reload

# ── ai-modules: deep-trace ────────────────────────────────────────────────────
dev-trace:
	./venv/bin/uvicorn ai-modules.deep_trace.main:app --host 0.0.0.0 --port 9002 --reload

# ── ai-modules: doc-guard (standalone, legacy) ───────────────────────────────
dev-guard:
	cd ai-modules && ../venv/bin/uvicorn doc_guard.main:app --host 0.0.0.0 --port 9003 --reload

# ── services: core API ────────────────────────────────────────────────────────
dev-core:
	./venv/bin/uvicorn services.core_api.main:app --host 0.0.0.0 --port 9000 --reload

# ── KAVACH Integrated Platform (fir-warden + net-watch + doc-guard) ──────────
# Runs the full unified backend — FIR Warden, Net-Watch, Doc-Guard, Blockchain
# and serves the built-in dashboard at http://localhost:8000
kavach:
	./venv/bin/python ai-modules/run.py

dev-kavach:
	./venv/bin/python ai-modules/run.py --reload

# ── Blockchain ────────────────────────────────────────────────────────────────
chain-node:
	cd blockchain && npx hardhat node

chain-deploy:
	cd blockchain && npx hardhat run scripts/deploy.js --network localhost

# End of Makefile
