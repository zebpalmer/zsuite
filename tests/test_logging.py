import logging
from unittest.mock import patch

import pytest

from zsuite import setup_logging
from zsuite.logging import DEFAULT_SUPPRESS_PACKAGES


def test_setup_logging_default(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    monkeypatch.setenv(
        "LOG_FORMAT",
        "%(asctime)s %(levelname)-8s %(name)-20s %(threadName)-10s : %(message)s",
    )

    with (
        patch("logging.StreamHandler") as mock_handler,
        patch("logging.Formatter") as mock_formatter,
        patch("logging.getLogger") as mock_get_logger,
        patch("logging.info") as mock_info,
    ):
        setup_logging()

        mock_handler.assert_called()
        mock_formatter.assert_called_with(
            "%(asctime)s %(levelname)-8s %(name)-20s %(threadName)-10s : %(message)s",
            datefmt="%Y-%m-%d %H:%M:%SZ",
        )
        mock_get_logger.assert_called()
        mock_info.assert_called_with("Logging level set to %s", "INFO")


def test_setup_logging_custom(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FORMAT", "custom_format")

    with (
        patch("logging.StreamHandler") as mock_handler,
        patch("logging.Formatter") as mock_formatter,
        patch("logging.getLogger") as mock_get_logger,
        patch("logging.info") as mock_info,
    ):
        setup_logging(log_level="DEBUG", log_format="custom_format")

        mock_get_logger.assert_called()
        mock_info.assert_called_with("Logging level set to %s", "DEBUG")

        mock_handler.assert_called()
        mock_formatter.assert_called_with("custom_format", datefmt="%Y-%m-%d %H:%M:%SZ")


def test_default_logging_setup(caplog, set_testing):
    """Test the default logging setup."""
    with caplog.at_level(logging.INFO):
        setup_logging()
        assert "Logging level set to INFO" in caplog.text
        assert caplog.records[0].levelname == "INFO"


def test_custom_log_level(caplog, set_testing):
    """Test logging setup with a custom log level."""
    custom_level = "DEBUG"
    with caplog.at_level(logging.DEBUG):
        setup_logging(log_level=custom_level)
        assert f"Logging level set to {custom_level}" in caplog.text
        assert logging.getLogger().getEffectiveLevel() == logging.DEBUG


def test_invalid_log_level():
    """Test logging setup with an invalid log level."""
    with pytest.raises(ValueError):
        setup_logging(log_level="INVALID")


def test_suppress_packages(caplog):
    """Test that package logging is suppressed correctly."""
    setup_logging(suppress_level="ERROR")
    for package in DEFAULT_SUPPRESS_PACKAGES:
        assert logging.getLogger(package).getEffectiveLevel() == logging.ERROR


def test_custom_suppress_packages(caplog):
    """Test custom packages are suppressed."""
    custom_packages = ["custom_package"]
    setup_logging(suppress_packages=custom_packages, suppress_level="CRITICAL")
    for package in custom_packages:
        assert logging.getLogger(package).getEffectiveLevel() == logging.CRITICAL
