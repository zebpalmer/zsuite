import logging
import os
import time

from .config import config_var

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


def setup_logging(
    log_level: str | None = None,
    log_format: str | None = None,
    suppress_packages: list[str] | None = None,
    suppress_level: str = "WARNING",
    force_utc: bool = True,
    dateformat: str | None = None,
) -> None:
    log_level = log_level or config_var("LOG_LEVEL", "INFO")
    dateformat = dateformat or ("%Y-%m-%d %H:%M:%SZ" if force_utc else "%Y-%m-%d %H:%M:%S")
    logging.Formatter.converter = time.gmtime if force_utc else time.localtime

    log_format = log_format or config_var("LOG_FORMAT", DEFAULT_LOG_FORMAT)

    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(f"Invalid log level: {log_level}")

    root_logger = logging.getLogger()

    # If TESTING is set, skip clearing handlers (for pytest/caplog compatibility)
    if os.environ.get("TESTING") == "true":
        logging.info("TESTING is set")
    else:
        # Resetting logging configuration to a known state
        root_logger.handlers.clear()

    # Configure new logging handler
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(log_format, datefmt=dateformat))
    root_logger.addHandler(handler)
    root_logger.setLevel("INFO")  # Ensure setup_logging always logs setup
    logging.info("Logging level set to %s", log_level)
    root_logger.setLevel(log_level)

    supress_package_logs(suppress_level, suppress_packages)


def supress_package_logs(suppress_level, suppress_packages):
    # Suppress specific package logging
    suppress_packages = suppress_packages or DEFAULT_SUPPRESS_PACKAGES
    for pkg in suppress_packages:
        logging.getLogger(pkg).setLevel(suppress_level)
