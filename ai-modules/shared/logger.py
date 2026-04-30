import logging
import os
import sys

# ANSI Color Codes
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

class KavachLogger:
    def __init__(self, name="KAVACH"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)
            self.logger.propagate = False

    def info(self, msg):
        self.logger.info(f"{Colors.GREEN}[OK]{Colors.RESET} {msg}")

    def warn(self, msg):
        self.logger.warning(f"{Colors.YELLOW}[WARN]{Colors.RESET} {msg}")

    def error(self, msg, exc_info=False):
        # We only show exc_info if explicitly asked or in a theoretical debug mode
        self.logger.error(f"{Colors.RED}[ERROR]{Colors.RESET} {msg}", exc_info=exc_info)

    def event(self, title, details):
        """
        Special block for threat detections or major system events.
        title: string
        details: dict of key-value pairs
        """
        print(f"\n{Colors.BOLD}{Colors.RED}🚨 {title.upper()}{Colors.RESET}")
        for k, v in details.items():
            print(f"  {Colors.CYAN}* {k}:{Colors.RESET} {v}")
        print("")

    def startup_header(self):
        print("\n" + "═"*60)
        print(f" {Colors.BOLD}🛡️  KAVACH SYSTEM STARTED{Colors.RESET}")
        print("═"*60 + "\n")

# Global instance
logger = KavachLogger()

def setup_uvicorn_logging():
    """
    Suppress noisy uvicorn access and info logs.
    """
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.ERROR)
