import logging
import re

logger = logging.getLogger(__name__)


class TrapdoorDetector:
    def __init__(self):
        self.suspicious_patterns = [
            r'sudo\s+(?!.*--valid-flag)',  # Unsafe sudo usage
            r'chmod\s+[0-7][0-7][0-7]\s+/etc/',  # Critical file permissions
            r'su\s+(root|admin)'  # Privilege escalation
        ]

    def analyze_logs(self, log_path: str = "system_logs.txt") -> list[str]:
        try:
            with open(log_path, 'r') as f:
                return [line.strip() for line in f
                        if any(re.search(pattern, line)
                        for pattern in self.suspicious_patterns)]
        except FileNotFoundError:
            raise SystemError(f"Log file {log_path} not found")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    detector = TrapdoorDetector()
    alerts = detector.analyze_logs()
    if alerts:
        for alert in alerts:
            logger.info("Trapdoor detected: %s", alert)
    else:
        logger.info("No trapdoors detected")
