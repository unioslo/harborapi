import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
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
@given(st.builds(UserResp), st.builds(UserResp))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_users(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user1: UserResp,
    user2: UserResp,
):
    httpserver.expect_request("/users").respond_with_json([user1.dict(), user2.dict()])
    async_client.url = httpserver.url_for("")
    users = await async_client.get_users()
    assert len(users) == 2
    assert users[0] == user1
    assert users[1] == user2
