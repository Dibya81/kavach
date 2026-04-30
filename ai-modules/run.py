"""
ai-modules/run.py
KAVACH startup bootstrap.

Now unified into a single process for easier hosting and lower resource usage.
Starts the main FIR-Warden app which has Sentinel and DeepTrace mounted.
"""

import sys
import os
import argparse
import time
import uvicorn
from shared.logger import logger, setup_uvicorn_logging, Colors

_HERE = os.path.dirname(os.path.abspath(__file__))   # ai-modules/

# Add ai-modules to path
sys.path.append(_HERE)

def check_blockchain():
    """Import and check blockchain status."""
    try:
        from fir_warden.blockchain import init_web3, get_chain_status
        init_web3()
        status = get_chain_status()
        if status.get("connected"):
            logger.info(f"Blockchain: Connected ({status.get('network')})")
        else:
            logger.warn("Blockchain: Not connected (Mock Mode)")
    except Exception as e:
        logger.error(f"Blockchain status check failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KAVACH Unified Backend Launcher")
    parser.add_argument("--host",   default="0.0.0.0")
    parser.add_argument("--port",   type=int, default=int(os.environ.get("PORT", 7860)))
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    try:
        logger.startup_header()
        setup_uvicorn_logging()
        
        # Check Blockchain
        check_blockchain()
        
        # Initialize Local Database
        from fir_warden.database import init_db
        init_db()
        logger.info("Database: Connected (Local SQLite)")
        print("")

        logger.info(f"KAVACH Unified: Starting on Port {args.port}")
        print(f"{Colors.CYAN}UI: http://localhost:3000{Colors.RESET}\n")

        # Run the unified app
        # fir_warden.main:app has Sentinel and DeepTrace mounted
        uvicorn.run("fir_warden.main:app", host=args.host, port=args.port, reload=args.reload)

    except KeyboardInterrupt:
        print("\n🛑 Shutting down KAVACH services...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Startup error: {e}")
        sys.exit(1)
