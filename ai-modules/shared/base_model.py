import json
import time

class BaseModule:
    def __init__(self, name: str):
        self.name = name
        self.start_time = time.time()

    def get_status(self):
        return {
            "module": self.name,
            "uptime": time.time() - self.start_time,
            "status": "active"
        }

    def log_event(self, event_type: str, data: dict):
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "module": self.name,
            "type": event_type,
            "data": data
        }
        print(f"[EVENT] {json.dumps(event)}")
