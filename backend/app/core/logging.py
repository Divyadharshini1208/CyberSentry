"""SentinelX Logging Configuration
Provides structured logging and secret masking for API keys, passwords, and tokens.
"""

import logging
import re
import sys
from typing import Any

# Patterns to mask in logs
SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)'),
    re.compile(r'(?i)(bearer\s+)([A-Za-z0-9\-_\.=]+)()'),
    re.compile(r'(?i)(password\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)'),
    re.compile(r'(?i)(secret\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)'),
]


class SecretMaskingFilter(logging.Filter):
    """Filters log records to mask credentials and sensitive tokens."""
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern in SENSITIVE_PATTERNS:
                record.msg = pattern.sub(r'\1***REDACTED***\3', record.msg)
        return True


def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("sentinelx")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s:%(module)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S"
        )
        handler.setFormatter(formatter)
        handler.addFilter(SecretMaskingFilter())
        logger.addHandler(handler)

    return logger


logger = setup_logging()
