import os

import pytest
from _pytest.logging import LogCaptureFixture
from hypothesis import Verbosity, settings
from loguru import logger

from harborapi.client import HarborAsyncClient

from .strategies import init_strategies

# Init custom hypothesis strategies
init_strategies()

# Hypothesis profiles
settings.register_profile("ci", settings(max_examples=1000))
settings.register_profile(
    "debug",
    settings(
        max_examples=10,
        verbosity=Verbosity.verbose,
    ),
)
settings.register_profile("dev", max_examples=10)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "default"))


@pytest.fixture(scope="session")
def async_client() -> HarborAsyncClient:
    return HarborAsyncClient(
        username="username", secret="secret", url="http://localhost"
    )


@pytest.fixture
def caplog(caplog: LogCaptureFixture):
    # https://loguru.readthedocs.io/en/stable/resources/migration.html#making-things-work-with-pytest-and-caplog
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)
