# I am somewhat clueless about best practices for configuring logging for a library.
# The contents of this module are derived from a conversation with ChatGPT (GPT-4).
# NOTE: multiple clients with different `logging` argument values will
# cause problems. However, users should not be creating multiple clients, so
# this should not be an issue. If it is, we can add a warning.
from __future__ import annotations

import logging

DEFAULT_LEVEL = logging.INFO
DEFAULT_LEVEL_DISABLED = logging.CRITICAL

logger = logging.getLogger("harborapi")


def enable_logging(level: int = DEFAULT_LEVEL) -> None:
    """Enable logging for 'harborapi'.

    Parameters
    ----------
    level : int
        The logging level, by default logging.INFO
    """
    logger.setLevel(level)
    handler = logging.StreamHandler()  # Logs to stderr by default
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    if logger.hasHandlers():
        logger.handlers.clear()  # Remove existing handlers
    logger.addHandler(handler)


def disable_logging() -> None:
    """Disable logging for 'harborapi'"""
    logger.setLevel(DEFAULT_LEVEL_DISABLED)
    if logger.hasHandlers():
        logger.handlers.clear()  # Remove existing handlers
    # Add a null handler to prevent "No handler found" warnings
    logger.addHandler(logging.NullHandler())


# Disable logging by default
disable_logging()
