import logging

logger = logging.getLogger(__name__)


def log_alert(vulnerability_type: str, details: str, severity: str = "Medium") -> None:
    """
    Logs an alert with details about the detected vulnerability.

    Args:
        vulnerability_type: The type of vulnerability detected (e.g., "Buffer Overflow").
        details: Additional information about the vulnerability.
        severity: The severity of the alert (e.g., "Critical", "High", "Medium", "Low").
    """
    alert_message = f"Vulnerability Detected: {vulnerability_type} | Severity: {severity} | Details: {details}"
    logger.info("%s", alert_message)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    log_alert("Buffer Overflow", "Detected in vulnerable_function() while processing user input.", "High")
    log_alert("Trapdoor", "Unauthorized privilege escalation detected in system logs.", "Critical")
