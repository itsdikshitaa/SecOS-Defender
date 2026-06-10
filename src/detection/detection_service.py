import json
import logging
import os
import random
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class DetectionService:
    def __init__(self):
        self.alert_log_file = os.path.join(os.path.dirname(__file__), "../alert/alerts.json")
        self.initialized = False
        self.running = False
        self._lock = threading.Lock()

        os.makedirs(os.path.dirname(self.alert_log_file), exist_ok=True)

        # Initialize alert log if it doesn't exist
        if not os.path.exists(self.alert_log_file):
            with open(self.alert_log_file, "w") as f:
                json.dump([], f)
        else:
            self._ensure_valid_json()

        self.initialized = True
        logger.info("Detection Service initialized successfully.")

    def _ensure_valid_json(self):
        """Ensure the alerts JSON file is valid under lock, fixing it if necessary."""
        with self._lock:
            try:
                with open(self.alert_log_file, "r") as f:
                    json.load(f)
                return
            except json.JSONDecodeError:
                logger.warning("Alerts file is corrupted. Attempting to fix...")
                try:
                    with open(self.alert_log_file, "r") as f:
                        content = f.read()

                    if "]" in content:
                        valid_content = content[: content.rindex("]") + 1]
                        json.loads(valid_content)
                        with open(self.alert_log_file, "w") as f:
                            f.write(valid_content)
                        logger.info("Successfully fixed corrupted alerts file.")
                        return
                except Exception as e:
                    logger.error("Could not repair the JSON file: %s", e)

                logger.warning("Creating new alerts file due to irrecoverable corruption.")
                with open(self.alert_log_file, "w") as f:
                    json.dump([], f)

    def _monitor_loop(self, vuln_type: str, message: str, severity: str, probability: float, interval: int):
        """Generic monitoring loop for vulnerability types."""
        while self.running:
            logger.debug("Monitoring for %s vulnerabilities...", vuln_type)
            if random.random() < probability:
                self.generate_alert(vuln_type, message, severity)
            time.sleep(interval)

    def monitor_buffer_overflow(self):
        self._monitor_loop("Buffer Overflow", "Potential buffer overflow detected in system call", "High", 0.3, 5)

    def monitor_trapdoor(self):
        self._monitor_loop("Trapdoor", "Suspicious backdoor activity detected", "Critical", 0.2, 7)

    def monitor_cache_poisoning(self):
        self._monitor_loop("Cache Poisoning", "Possible ARP cache poisoning attempt", "Medium", 0.25, 6)

    def generate_alert(self, alert_type: str, message: str, severity: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {"timestamp": timestamp, "type": alert_type, "message": message, "severity": severity}

        MAX_RETRIES = 3
        for attempt in range(MAX_RETRIES):
            try:
                with self._lock:
                    self._ensure_valid_json()
                    with open(self.alert_log_file, "r") as f:
                        alerts = json.load(f)
                    alerts.append(alert)
                    with open(self.alert_log_file, "w") as f:
                        json.dump(alerts, f, indent=2)

                logger.info("ALERT %s - %s: %s", severity, alert_type, message)
                return
            except Exception as e:
                logger.error("Error generating alert (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, e)
                time.sleep(0.5)

        logger.error("Failed to generate alert after %d attempts", MAX_RETRIES)

    def start(self):
        if not self.initialized:
            logger.error("Detection Service not initialized")
            return False

        self.running = True
        logger.info("Starting Detection Service...")

        threading.Thread(target=self.monitor_buffer_overflow, daemon=True).start()
        threading.Thread(target=self.monitor_trapdoor, daemon=True).start()
        threading.Thread(target=self.monitor_cache_poisoning, daemon=True).start()
        return True

    def stop(self):
        self.running = False
        logger.info("Detection Service stopped.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    service = DetectionService()
    service.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop()
