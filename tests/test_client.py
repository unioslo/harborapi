import asyncio

import pytest
from pydantic import ValidationError
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient, construct_model
from harborapi.model import UserResp


# TODO: parametrize this to test both clients
@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://harbor.example.com", "https://harbor.example.com/api/v2.0"),
        ("https://harbor.example.com/api", "https://harbor.example.com/api/v2.0"),
        ("https://harbor.example.com/api/", "https://harbor.example.com/api/v2.0"),
        ("https://harbor.example.com/api/v2.0/", "https://harbor.example.com/api/v2.0"),
        # should have regex to check for valid URL, as this likely isn't a valid URL vvvv
        ("https://harbor.example.com/api/v", "https://harbor.example.com/api/v"),
    ],
)
def test_client_init_url(url: str, expected: str):
    # manually set version to v2.0 for this test
    client = HarborAsyncClient(
        username="username", token="token", url=url, version="v2.0"
    )
    assert client.url == expected


def test_client_init_sanity():
    client = HarborAsyncClient(
        username="username", token="token", url="https://harbor.example.com"
    )
    assert client.url == "https://harbor.example.com/api/v2.0"
    assert client.username == "username"
    assert client.token == "token"


@pytest.mark.asyncio
async def test_get_pagination_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test pagination by mocking paginated /users results."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": "/users?page=2"},
    )
    httpserver.expect_request(
        "/api/v2.0/users", query_string="page=2"
    ).respond_with_json([{"username": "user3"}, {"username": "user4"}])
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users")  # type: ignore
    assert isinstance(users, list)
    assert len(users) == 4
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"
    assert users[2]["username"] == "user3"
    assert users[3]["username"] == "user4"


@pytest.mark.asyncio
async def test_get_pagination_invalid_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    caplog: pytest.LogCaptureFixture,
):
    """Test pagination where subsequent page returns non-list results."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": "/users?page=2"},
    )
    # Next page does not return a list, so we ignore it
    httpserver.expect_request(
        "/api/v2.0/users", query_string="page=2"
    ).respond_with_json({"username": "user3"})
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users")  # type: ignore
    assert isinstance(users, list)
    assert len(users) == 2
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"
    assert "Unable to handle paginated results" in caplog.text


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

    httpserver.expect_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users")
    assert isinstance(users, list)
    assert len(users) == 2


@pytest.mark.asyncio
async def test_construct_model():
    # TODO: test create_model with all models
    m = construct_model(UserResp, {"username": "user1"})
    assert isinstance(m, UserResp)
    assert m.username == "user1"

    # Invalid value for "username"
    with pytest.raises(ValidationError) as e:
        construct_model(UserResp, {"username": {}})
    assert e.value.errors()[0]["loc"] == ("username",)
    assert len(e.value.errors()) == 1


@pytest.mark.asyncio
async def test_get_invalid_data(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Tests handling of data from the server that does not match the schema."""
    httpserver.expect_request("/api/v2.0/users").respond_with_json(
        [{"username": {}}, {"username": "user2"}],
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    with pytest.raises(ValidationError) as e:
        await async_client.get_users()
    assert e.value.errors()[0]["loc"] == ("username",)
    assert len(e.value.errors()) == 1
