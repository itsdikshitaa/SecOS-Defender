import json
import logging
import subprocess
import shlex

logger = logging.getLogger(__name__)


class StaticAnalyzer:
    def __init__(self):
        self.tools = {
            "semgrep": ["semgrep", "--config", "auto", "--json"],
            "bandit": ["bandit", "-r", ".", "-f", "json"],
        }

    def run_scan(self, tool: str) -> dict:
        """
        Run a static analysis scan using the specified tool.

        Args:
            tool: Name of the tool to run ("semgrep" or "bandit").

        Returns:
            Parsed JSON output from the tool.

        Raises:
            ValueError: If the tool name is unknown.
            subprocess.CalledProcessError: If the tool returns a non-zero exit code.
        """
        if tool not in self.tools:
            raise ValueError(f"Unknown tool: {tool}. Available: {list(self.tools.keys())}")

        try:
            result = subprocess.run(
                self.tools[tool],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                logger.warning("%s exited with code %d: %s", tool, result.returncode, result.stderr.strip())
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError as e:
            logger.error("Failed to parse %s output as JSON: %s", tool, e)
            return {}
        except subprocess.TimeoutExpired:
            logger.error("%s scan timed out after 300 seconds", tool)
            return {}
