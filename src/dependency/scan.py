import json
import logging
import time

import requests

logger = logging.getLogger(__name__)


class DependencyScanner:
    # NVD API v2.0 — v1.0 was deprecated in 2024
    CVE_API_V2 = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def check_vulnerability(self, package_name: str, api_key: str = "") -> list[dict]:
        """
        Query the NVD API v2.0 for CVEs affecting a given package.

        Args:
            package_name: Name of the software package to scan.
            api_key: Optional NVD API key for higher rate limits.

        Returns:
            List of CVE items matching the package.
        """
        params = {"keywordSearch": package_name, "keywordExactMatch": True}
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        try:
            response = requests.get(
                self.CVE_API_V2,
                params=params,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            logger.info("Found %d CVEs for package %s", len(vulnerabilities), package_name)
            return vulnerabilities
        except requests.exceptions.Timeout:
            logger.error("NVD API request timed out for package %s", package_name)
            return []
        except requests.exceptions.HTTPError as e:
            logger.error("NVD API HTTP error for %s: %s", package_name, e)
            return []
        except json.JSONDecodeError as e:
            logger.error("NVD API returned invalid JSON for %s: %s", package_name, e)
            return []
        except Exception as e:
            logger.error("Unexpected error scanning %s: %s", package_name, e)
            return []
