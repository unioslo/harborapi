import pytest
from _pytest.logging import LogCaptureFixture
from loguru import logger

from harborapi.client import HarborAsyncClient


@pytest.fixture(scope="session")
def async_client() -> HarborAsyncClient:
    return HarborAsyncClient(username="username", token="token", url="http://localhost")


@pytest.fixture
def caplog(caplog: LogCaptureFixture):
    # https://loguru.readthedocs.io/en/stable/resources/migration.html#making-things-work-with-pytest-and-caplog
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)
