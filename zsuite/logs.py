"""Standardized logging configuration setup"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

__all__ = ["setup_logging"]

VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
DEFAULT_SUPPRESS_PACKAGES = [
    "urllib3",
    "requests",
    "pymongo",
    "apscheduler",
    "selenium",
    "werkzeug",
]
DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)-20s %(threadName)-10s %(funcName)s : %(message)s"
VALID_LOG_MODES = ["human", "json"]
DEFAULT_LOG_MODE = "human"
_LOGGING_INITIALIZED = False


class JsonFormatter(logging.Formatter):
    """Format logs as JSON objects for structured logging systems."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "thread": record.threadName,
            "function": record.funcName,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


def setup_logging(
    log_level: str | None = None,
    log_format: str | None = None,
    suppress_packages: list[str] | None = None,
    suppress_level: str = "WARNING",
    force_utc: bool = True,
    dateformat: str | None = None,
    log_file: str | Path | None = None,
    log_mode: str | None = None,
) -> None:
    """Configure application-wide logging with customizable format and output options.

    Sets up the root logger with specified level, format, and handlers. Supports both
    standard text and JSON logging formats, optional file output, and selective
    suppression of third-party package logs.

    :param log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). If None,
                      uses LOG_LEVEL config variable or defaults to INFO.
    :param log_format: Custom log format string. Ignored when log_mode is 'json'.
    :param suppress_packages: List of package names to suppress.
    :param suppress_level: Log level to apply to suppressed packages. Defaults to WARNING.
    :param force_utc: If True, uses UTC timestamps in logs.
    :param dateformat: Custom date format string.
    :param log_file: Optional file path for writing logs.
    :param log_mode: Logging format mode ('json' or 'human').
    :raises ValueError: If log_level is not a valid level.
    :raises ValueError: If log_mode is not in VALID_LOG_MODES.
    """
    from .config import config_var

    global _LOGGING_INITIALIZED
    log_level = log_level or config_var("LOG_LEVEL", "INFO")
    dateformat = dateformat or ("%Y-%m-%d %H:%M:%SZ" if force_utc else "%Y-%m-%d %H:%M:%S")
    logging.Formatter.converter = time.gmtime if force_utc else time.localtime

    log_mode = log_mode or config_var("LOG_MODE", DEFAULT_LOG_MODE)
    if log_mode not in VALID_LOG_MODES:
        raise ValueError(f"Invalid log mode: {log_mode}. Valid modes are: {', '.join(VALID_LOG_MODES)}")

    log_format = log_format or config_var("LOG_FORMAT", DEFAULT_LOG_FORMAT)

    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(f"Invalid log level: {log_level}")

    root_logger = logging.getLogger()

    # If TESTING is set, skip clearing handlers (for pytest/caplog compatibility)
    if os.environ.get("TESTING") == "true":
        logging.info("TESTING is set")
    else:
        root_logger.handlers.clear()

    stream_handler = logging.StreamHandler()
    formatter = JsonFormatter() if log_mode == "json" else logging.Formatter(log_format, datefmt=dateformat)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        logging.debug(f"Logs will be written to {log_file}")

    root_logger.setLevel("INFO")  # Ensure setup_logging always logs setup
    logging.info("Logging level set to %s", log_level)
    root_logger.setLevel(log_level)

    supress_package_logs(suppress_level, suppress_packages)
    _LOGGING_INITIALIZED = True


def supress_package_logs(suppress_level, suppress_packages):
    """Suppress specific package logging to the specified level."""
    suppress_packages = suppress_packages or DEFAULT_SUPPRESS_PACKAGES
    for pkg in suppress_packages:
        logging.getLogger(pkg).setLevel(suppress_level)


def log_or_print(message: str, level: str = "INFO") -> None:
    """Log message if logging is initialized, otherwise print to stdout.

    :param message: Message to log or print.
    :param level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.
    """
    if _LOGGING_INITIALIZED:
        logger = logging.getLogger()
        log_method = getattr(logger, level.lower(), logger.info)
        log_method(message)
    else:
        print(f"{level} -- {message}")
