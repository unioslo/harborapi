import logging
import os
import warnings
from typing import Optional

import pytest

from harborapi import HarborAsyncClient
from harborapi.log import (
    DEFAULT_LEVEL,
    DEFAULT_LEVEL_DISABLED,
    disable_logging,
    enable_logging,
    logger,
)

# TODO: ensure we are testing the logger properly (we are using the global logger object)
# Should we import logger in each test function?


def test_disable_logging(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture
) -> None:
    """Test disable_logging()"""
    disable_logging()

    # Logger should be set to critical
    assert logger.level == logging.CRITICAL == DEFAULT_LEVEL_DISABLED
    assert len(logger.handlers) == 1
    logger.critical("Test")
    assert len(caplog.records) == 1  # still captured by caplog
    captured = capsys.readouterr()
    assert captured.err == ""


def test_enable_logging(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture
) -> None:
    """Test enable_logging()"""
    disable_logging()  # Make sure we have disabled logging first
    logger.info("Test 1")
    assert len(caplog.records) == 0

    # A critical log will not go to stderr, but will create a log record
    logger.critical("Test 1")
    captured = capsys.readouterr()
    assert captured.err == ""
    # but it actually logs, so we should have 1 record in caplog
    assert len(caplog.records) == 1

    # Now enable logging
    enable_logging()
    assert logger.level == logging.INFO == DEFAULT_LEVEL
    assert len(logger.handlers) == 1
    logger.critical("Test 2")

    # We logged a critical log while disabled (but it didnt go to stderr)
    # So we should have 2 records in caplog
    assert len(caplog.records) == 2
    assert caplog.records[1].message == "Test 2"
    captured = capsys.readouterr()
    assert "Test 2" in captured.err


def test_enable_logging_with_level(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture
) -> None:
    """Test enable_logging() with a custom level"""
    # Enable logger at debug level
    enable_logging(level=logging.DEBUG)
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) == 1
    logger.debug("Test 1")
    assert len(caplog.records) == 1  # logged due to level
    captured = capsys.readouterr()
    assert "Test 1" in captured.err

    # Now increase the level and and log with debug again
    enable_logging(level=logging.INFO)
    assert logger.level == logging.INFO
    logger.debug("Test 2")
    assert len(caplog.records) == 1  # did not log due to level
    captured = capsys.readouterr()
    assert captured.err == ""


def test_enable_logging_multiple_calls(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture
) -> None:
    # Ensure no warnings are emitted
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        enable_logging()
        enable_logging()
        enable_logging()

    logger.info("Test after multiple calls")
    assert len(caplog.records) == 1
    captured = capsys.readouterr()
    assert "Test after multiple calls" in captured.err


def test_disable_logging_multiple_calls(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture
) -> None:
    # Ensure no warnings are emitted
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        disable_logging()
        disable_logging()
        disable_logging()

    logger.info("Test after multiple calls")
    assert len(caplog.records) == 0
    captured = capsys.readouterr()
    assert captured.err == ""


@pytest.mark.parametrize("logging_enabled", [None, False])
def test_client_logging_disabled(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture,
    logging_enabled: Optional[bool],
) -> None:
    """Tests client when logging is disabled.
    Tests by passing in  logging=False and omitting the logging kwarg.
    Both should keep logging disabled."""
    kwargs = {"logging": logging_enabled} if logging_enabled is not None else {}
    HarborAsyncClient(
        url="https://example.com/api/v2.0", username="test", secret="test", **kwargs
    )
    assert logger.level == logging.CRITICAL == DEFAULT_LEVEL_DISABLED
    assert len(logger.handlers) == 1

    logger.critical("Test critical")
    logger.info("Test info")

    assert len(caplog.records) == 1  # critical still captured by caplog
    assert caplog.records[0].message == "Test critical"
    captured = capsys.readouterr()
    assert captured.err == ""


def test_client_logging_enabled(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture,
) -> None:
    """Tests client when logging is enabled."""
    HarborAsyncClient(
        url="https://example.com/api/v2.0", username="test", secret="test", logging=True
    )
    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1

    logger.critical("Test critical")
    logger.info("Test info")

    assert len(caplog.records) == 2
    assert caplog.records[0].message == "Test critical"
    assert caplog.records[1].message == "Test info"
    captured = capsys.readouterr()
    assert "Test critical" in captured.err
    assert "Test info" in captured.err


# NOTE: Could refactor into 5 tests, but this lets us test that modifying
# the envvar/logging arg behaves as expected for repeated instantiations
def test_client_logging_envvar(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture
) -> None:
    """Tests that the client respects the HARBORAPI_LOGGING envvar, and that
    it takes priority over the logging arg."""
    assert "HARBORAPI_LOGGING" not in os.environ

    # No envvar set, no logging arg passed (Disabled)
    disable_logging()  # Make sure we have disabled logging first (other tests may have enabled it)
    HarborAsyncClient(
        url="https://example.com/api/v2.0", username="username", secret="secret"
    )
    assert logger.level == logging.CRITICAL == DEFAULT_LEVEL_DISABLED
    logger.info("Disabled")
    assert len(caplog.records) == 0
    captured = capsys.readouterr()
    assert captured.err == ""

    # Envvar set, no logging arg passed (Enabled)
    os.environ["HARBORAPI_LOGGING"] = "1"
    HarborAsyncClient(
        url="https://example.com/api/v2.0", username="username", secret="secret"
    )
    assert logger.level == logging.INFO == DEFAULT_LEVEL
    logger.info("Envvar, no arg")
    assert len(caplog.records) == 1
    assert caplog.records[0].message == "Envvar, no arg"
    captured = capsys.readouterr()
    assert "Envvar, no arg" in captured.err

    # Envvar set, logging=False arg passed (Enabled)
    disable_logging()  # disable logging first
    os.environ["HARBORAPI_LOGGING"] = "1"
    HarborAsyncClient(
        url="https://example.com/api/v2.0",
        username="username",
        secret="secret",
        logging=False,
    )
    assert logger.level == logging.INFO == DEFAULT_LEVEL
    logger.info("Envvar, arg=False")
    assert len(caplog.records) == 2  # previous + 1
    assert caplog.records[1].message == "Envvar, arg=False"
    captured = capsys.readouterr()
    assert "Envvar, arg=False" in captured.err

    # Envvar set, logging=True arg passed (Enabled)
    disable_logging()  # disable logging first
    os.environ["HARBORAPI_LOGGING"] = "1"
    HarborAsyncClient(
        url="https://example.com/api/v2.0",
        username="username",
        secret="secret",
        logging=True,
    )
    assert logger.level == logging.INFO == DEFAULT_LEVEL
    logger.info("Envvar, arg=True")
    assert len(caplog.records) == 3  # previous + 1
    assert caplog.records[2].message == "Envvar, arg=True"
    captured = capsys.readouterr()
    assert "Envvar, arg=True" in captured.err

    # No envvar set, logging=True arg passed (Enabled)
    os.environ.pop("HARBORAPI_LOGGING")
    disable_logging()
    HarborAsyncClient(
        url="https://example.com/api/v2.0",
        username="username",
        secret="secret",
        logging=True,
    )

    assert logger.level == logging.INFO == DEFAULT_LEVEL
    logger.info("No envvar, arg=True")
    assert len(caplog.records) == 4  # previous + 1
    assert caplog.records[3].message == "No envvar, arg=True"
    captured = capsys.readouterr()
    assert "No envvar, arg=True" in captured.err
