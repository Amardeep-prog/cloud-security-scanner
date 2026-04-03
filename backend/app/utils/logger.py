"""
Logger Utility
==============
Configures structured JSON logging for the application.
In production, outputs JSON for easy ingestion by CloudWatch Insights.
"""

import logging
import sys
from app.config import settings


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for the given module name."""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Already configured

    level = logging.DEBUG if settings.DEBUG else logging.INFO
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if settings.ENVIRONMENT == "production":
        # JSON format for CloudWatch Logs Insights
        fmt = logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
        )
    else:
        # Human-readable for development
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.propagate = False
    return logger
