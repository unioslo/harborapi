import pytest

from harborapi.client import HarborAsyncClient


@pytest.fixture(scope="session")
def async_client() -> HarborAsyncClient:
    return HarborAsyncClient(username="username", token="token", url="http://localhost")
