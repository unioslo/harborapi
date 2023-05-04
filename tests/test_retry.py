import asyncio

import pytest
from backoff._typing import Details
from httpx import ConnectError
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.exceptions import HarborAPIException, StatusError
from harborapi.retry import RetrySettings, get_backoff_kwargs


def test_retrysettings_basic():
    retry = RetrySettings(
        max_tries=5,
        max_time=120,
    )
    assert retry.max_tries == 5
    assert retry.max_time == 120


def test_retrysettings_exception_single():
    retry = RetrySettings(
        exception=StatusError,
    )
    assert retry.exception == StatusError


def test_retrysettings_exception_single_tuple():
    retry = RetrySettings(
        exception=(StatusError,),
    )
    assert retry.exception == (StatusError,)


def test_retrysettings_exception_multiple():
    retry = RetrySettings(
        exception=(StatusError, HarborAPIException),
    )
    assert retry.exception == (StatusError, HarborAPIException)


def test_retrysettings_exception_multiple_list():
    retry = RetrySettings(
        exception=[StatusError, HarborAPIException],
    )
    assert retry.exception == (StatusError, HarborAPIException)


# TODO: fuzz with hypothesis if needed
def test_get_backoff_kwargs(async_client: HarborAsyncClient) -> None:
    def wait_gen(value: float) -> float:
        return 1 + value

    def jitter(value: float) -> float:
        return value + 1

    def giveup(e: Exception) -> bool:
        return False

    def on_backoff(details: Details) -> None:
        pass

    def on_success(details: Details) -> None:
        pass

    def on_giveup(details: Details) -> None:
        pass

    retry = RetrySettings(
        exception=Exception,
        max_tries=5,
        max_time=120,
        wait_gen=wait_gen,
        jitter=jitter,
        giveup=giveup,
        on_success=on_success,
        on_backoff=on_backoff,
        on_giveup=on_giveup,
        raise_on_giveup=False,
        value=2,
    )
    async_client.retry = retry

    kwargs = get_backoff_kwargs(async_client)
    assert kwargs["exception"] == Exception
    assert kwargs["max_tries"] == 5
    assert kwargs["max_time"] == 120
    assert kwargs["wait_gen"] == wait_gen
    assert kwargs["jitter"] == jitter
    assert kwargs["giveup"] == giveup
    assert kwargs["on_success"] == on_success
    assert kwargs["on_backoff"] == on_backoff
    assert kwargs["on_giveup"] == on_giveup
    assert kwargs["raise_on_giveup"] is False
    assert kwargs["value"] == 2


@pytest.mark.asyncio
async def test_get_retry_mock(async_client: HarborAsyncClient, httpserver: HTTPServer):
    """Test retry by mocking a server that is initially down, then comes up."""
    httpserver.stop()

    # this is a little hacky for now:
    # we schedule the server to start after a few seconds
    async def start_server():
        await asyncio.sleep(2)  # can be increased, but wastes CI run time
        httpserver.start()

    asyncio.create_task(start_server())

    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users")
    assert isinstance(users, list)
    assert len(users) == 2


@pytest.mark.asyncio
async def test_get_retry_disabled_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test that a ConnectError is raised when the server is down and
    retry is disabled."""
    httpserver.stop()

    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    async_client.retry = None  # disable retry
    with pytest.raises(ConnectError):
        users = await async_client.get("/users")
        assert isinstance(users, list)
        assert len(users) == 2


@pytest.mark.asyncio
async def test_get_retry_custom_wait_gen(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test that a ConnectError is raised when the server is down and
    retry is disabled."""
    httpserver.stop()

    async def start_server():
        await asyncio.sleep(0.5)  # can be increased, but wastes CI run time
        httpserver.start()

    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
    )

    # Simpler than using a mocker object
    call_count = 0

    def wait_gen():
        nonlocal call_count
        yield  # does not count towards call count
        while True:
            call_count += 1
            yield 0.01

    async_client.url = httpserver.url_for("/api/v2.0")
    async_client.retry.wait_gen = wait_gen

    # First call(s) should fail
    asyncio.create_task(start_server())
    users = await async_client.get("/users")

    assert isinstance(users, list)
    assert len(users) == 2
    # Generator should have been called more than once
    # since the first call just initializes it
    assert call_count >= 1


@pytest.mark.asyncio
async def test_no_retry_ctx_manager(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Tests that the `no_retry` context manager disables retrying for a request, then
    re-enables it after the request is complete."""
    httpserver.stop()

    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
    )

    async_client.url = httpserver.url_for("/api/v2.0")

    # assert we have active retry settings
    assert async_client.retry is not None
    assert async_client.retry.max_time or async_client.retry.max_tries
    assert async_client.retry.enabled

    with pytest.raises(ConnectError):
        with async_client.no_retry():
            assert async_client.retry is None
            users = await async_client.get("/users")
            assert isinstance(users, list)
            assert len(users) == 2

    # Start server again and assert that retry is enabled
    async def start_server():
        await asyncio.sleep(0.5)  # can be increased, but wastes CI run time
        httpserver.start()

    asyncio.create_task(start_server())
    users = await async_client.get("/users")
    assert isinstance(users, list)
    assert len(users) == 2
    assert async_client.retry.enabled
