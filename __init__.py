"""
SIEM-Lite: Log Correlation Engine
Main package initialization and version information.
"""

__version__ = "2.4.1"
__author__ = "SIEM-Lite Project"
__license__ = "MIT"

import os
import logging

# Package root directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
RULES_DIR = os.path.join(CONFIG_DIR, "rules")
DASHBOARDS_DIR = os.path.join(CONFIG_DIR, "dashboards")

# Default configuration file
DEFAULT_CONFIG_FILE = os.path.join(CONFIG_DIR, "siem.yaml")

# Severity levels aligned with syslog
SEVERITY_LEVELS = {
    "debug": 7,
    "info": 6,
    "notice": 5,
    "warning": 4,
    "error": 3,
    "critical": 2,
    "alert": 1,
    "emergency": 0,
}

SEVERITY_NAMES = {v: k for k, v in SEVERITY_LEVELS.items()}

# Log facility mapping
FACILITY_MAP = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}


def setup_logging(level=logging.INFO, log_file=None, fmt=None):
    """Configure root logging for the SIEM application.

    Args:
        level: Logging level (default INFO).
        log_file: Optional file path for log output.
        fmt: Optional custom format string.
    """
    if fmt is None:
        fmt = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"

    formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except (IOError, PermissionError) as exc:
            root_logger.warning("Could not open log file %s: %s", log_file, exc)

    return root_logger
