import logging
import os
import subprocess

logger = logging.getLogger(__name__)


class AutoPatcher:
    # Extensions that are safe to patch with sed (text source files)
    SAFE_EXTENSIONS = {".c", ".cpp", ".h", ".hpp", ".py"}

    def fix_buffer_overflow(self, file_path: str) -> bool:
        """Safely replace strcpy with strncpy in source files.

        Args:
            file_path: Path to source file to patch.

        Returns:
            True if patched successfully, False otherwise.
        """
        # Validate file exists
        if not os.path.isfile(file_path):
            logger.error("Cannot patch: file not found - %s", file_path)
            return False

        # Validate file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() not in self.SAFE_EXTENSIONS:
            logger.warning("Skipping %s: extension %s not in safe list", file_path, ext)
            return False

        # Check file is readable
        if not os.access(file_path, os.R_OK | os.W_OK):
            logger.error("Cannot patch: insufficient permissions on %s", file_path)
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            logger.error("Cannot read %s: %s", file_path, e)
            return False

        # Verify the file actually contains strcpy before running sed
        if "strcpy" not in content:
            logger.info("No strcpy found in %s, skipping", file_path)
            return False

        result = subprocess.run(
            ["sed", "-i", "--", "s/strcpy/strncpy/g", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.error("sed failed on %s: %s", file_path, result.stderr.strip())
            return False

        logger.info("Patched %s: Replaced strcpy with strncpy", file_path)
        return True
