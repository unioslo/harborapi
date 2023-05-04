from pathlib import Path
from typing import Optional

import pytest
from httpx import HTTPStatusError
from hypothesis import HealthCheck, given, settings
from pydantic import ValidationError
from pytest_httpserver import HTTPServer
from pytest_mock import MockerFixture

from harborapi.auth import HarborAuthFile
from harborapi.client import HarborAsyncClient
from harborapi.exceptions import (
    BadRequest,
    Forbidden,
    InternalServerError,
    NotFound,
    PreconditionFailed,
    StatusError,
    Unauthorized,
)
from harborapi.models import Error, Errors, UserResp
from harborapi.utils import get_basicauth

from .strategies import errors_strategy


# TODO: parametrize this to test both clients
@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://harbor.example.com/", "https://harbor.example.com"),
        ("https://harbor.example.com/api/", "https://harbor.example.com/api"),
        ("https://harbor.example.com/api/v2.0", "https://harbor.example.com/api/v2.0"),
        ("https://harbor.example.com/api/v2.0/", "https://harbor.example.com/api/v2.0"),
    ],
)
def test_client_init_url(url: str, expected: str):
    # manually set version to v2.0 for this test
    client = HarborAsyncClient(username="username", secret="secret", url=url)
    assert client.url == expected


def test_client_init_username():
    client = HarborAsyncClient(
        username="username", secret="secret", url="https://harbor.example.com/api/v2.0"
    )
    assert client.url == "https://harbor.example.com/api/v2.0"
    assert client.basicauth == get_basicauth("username", "secret")


def test_client_init_password_warning():
    with pytest.warns(DeprecationWarning) as warnings:
        client = HarborAsyncClient(
            username="username",
            password="password",
            url="https://harbor.example.com/api/v2.0",
        )
    assert len(warnings) == 1
    assert "password" in str(warnings[0].message)
    assert client.url == "https://harbor.example.com/api/v2.0"
    assert client.basicauth == get_basicauth("username", "password")


def test_client_init_credentials():
    with pytest.warns(DeprecationWarning) as warnings:
        client = HarborAsyncClient(
            credentials="dXNlcm5hbWU6c2VjcmV0",
            url="https://harbor.example.com/api/v2.0",
        )
    assert len(warnings) == 1
    assert "credentials" in str(warnings[0].message)
    assert client.url == "https://harbor.example.com/api/v2.0"
    assert client.basicauth == get_basicauth("username", "secret")


def test_client_init_credentials_superseded_by_basicauth():
    client = HarborAsyncClient(
        credentials="my_credentials",
        basicauth="my_basicauth",
        url="https://harbor.example.com/api/v2.0",
    )
    assert client.url == "https://harbor.example.com/api/v2.0"
    # `basicauth` should take precedence over `credentials`
    assert client.basicauth.get_secret_value() == "my_basicauth"


def test_client_init_basicauth():
    basicauth = "dXNlcm5hbWU6c2VjcmV0"
    client = HarborAsyncClient(
        basicauth=basicauth, url="https://harbor.example.com/api/v2.0"
    )
    assert client.url == "https://harbor.example.com/api/v2.0"
    assert client.basicauth.get_secret_value() == basicauth


def test_client_init_credentials_file(credentials_file: Path):
    client = HarborAsyncClient(
        credentials_file=credentials_file, url="https://harbor.example.com/api/v2.0"
    )
    assert client.url == "https://harbor.example.com/api/v2.0"
    assert client.basicauth == get_basicauth("robot$harborapi-test", "bad-password")


@pytest.mark.parametrize("url", [None, ""])
def test_client_init_url_empty_url(url: Optional[str]):
    with pytest.raises(ValueError) as e:
        HarborAsyncClient(url=url, username="user", secret="secret")  # type: ignore
    assert "url" in str(e.value).lower()


def test_client_init_no_credentials():
    with pytest.raises(ValueError) as e:
        HarborAsyncClient(url="https://harbor.example.com/api/v2.0")
    # just make sure it's different from the URL error
    assert "credentials" in str(e.value).lower()


@pytest.mark.skip(reason="TODO")
def test_client_init_credentials_file_not_found():
    pass


@pytest.mark.asyncio
async def test_get_pagination_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test pagination by mocking paginated /users results."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="next"'},
    )
    httpserver.expect_oneshot_request(
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
async def test_get_pagination_next_and_prev_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer
) -> None:
    """Test pagination links that contain both next and prev links."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="next"'},
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/users", query_string="page=2"
    ).respond_with_json(
        [{"username": "user3"}, {"username": "user4"}],
        headers={
            "link": '</api/v2.0/users?page=1>; rel="prev" , </api/v2.0/users?page=3>; rel="next"'
        },
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/users", query_string="page=3"
    ).respond_with_json(
        [{"username": "user5"}, {"username": "user6"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="prev"'},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users")
    assert isinstance(users, list)
    assert len(users) == 6
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"
    assert users[2]["username"] == "user3"
    assert users[3]["username"] == "user4"
    assert users[4]["username"] == "user5"
    assert users[5]["username"] == "user6"


@pytest.mark.asyncio
async def test_get_pagination_large_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test pagination with a large number of pages."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="next"'},
    )
    N_PAGES = 500
    for page in range(2, N_PAGES + 1):
        if page == N_PAGES:
            headers = {"link": f'</api/v2.0/users?page={page-1}>; rel="prev"'}
        else:
            headers = {"link": f'</api/v2.0/users?page={page+1}>; rel="next"'}
        httpserver.expect_oneshot_request(
            "/api/v2.0/users", query_string=f"page={page}"
        ).respond_with_json([{"username": f"user{page}"}], headers=headers)

    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users")
    assert isinstance(users, list)
    assert len(users) == N_PAGES


@pytest.mark.asyncio
async def test_get_pagination_no_follow(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test pagination by mocking paginated /users results."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="next"'},
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/users", query_string=f"page=2"
    ).respond_with_json(
        [{"username": "user3"}],
        headers={"link": '</api/v2.0/users?page=1>; rel="prev"'},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users", follow_links=False)  # type: ignore
    assert isinstance(users, list)
    assert len(users) == 2
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"


@pytest.mark.asyncio
async def test_get_pagination_limit(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test pagination by mocking paginated /users results."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="next"'},
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/users", query_string=f"page=2"
    ).respond_with_json(
        [{"username": "user3"}],
        headers={"link": '</api/v2.0/users?page=1>; rel="prev"'},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users", limit=2)  # type: ignore
    assert isinstance(users, list)
    assert len(users) == 2
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"


@pytest.mark.asyncio
async def test_get_pagination_no_limit(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Test pagination by mocking paginated /users results."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="next"'},
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/users", query_string=f"page=2"
    ).respond_with_json(
        [{"username": "user3"}],
        headers={"link": '</api/v2.0/users?page=1>; rel="prev"'},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users", limit=None)  # type: ignore
    assert isinstance(users, list)
    assert len(users) == 3
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"
    assert users[2]["username"] == "user3"


@pytest.mark.asyncio
async def test_get_pagination_invalid_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    caplog: pytest.LogCaptureFixture,
):
    """Test pagination where subsequent page returns non-list results."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        headers={"link": '</api/v2.0/users?page=2>; rel="next"'},
    )
    # Next page does not return a list, so we ignore it
    httpserver.expect_oneshot_request(
        "/api/v2.0/users", query_string="page=2"
    ).respond_with_json(
        {"username": "user3"},
        headers={"link": '</api/v2.0/users?page=1>; rel="prev"'},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get("/users")  # type: ignore
    assert isinstance(users, list)
    assert len(users) == 2
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"
    assert "Unable to handle paginated results" in caplog.text


@pytest.mark.asyncio
async def test_construct_model(async_client: HarborAsyncClient, mocker: MockerFixture):
    c = async_client
    construct_spy = mocker.spy(UserResp, "construct")
    parse_spy = mocker.spy(UserResp, "parse_obj")

    # TODO: test create_model with all models
    m = c.construct_model(UserResp, {"username": "user1"})
    assert isinstance(m, UserResp)
    assert m.username == "user1"
    assert parse_spy.call_count == 1
    assert construct_spy.call_count == 0

    # Invalid value for "username"
    with pytest.raises(ValidationError) as e:
        c.construct_model(UserResp, {"username": {}})
    assert e.value.errors()[0]["loc"] == ("username",)
    assert len(e.value.errors()) == 1
    assert parse_spy.call_count == 2
    assert construct_spy.call_count == 0


@pytest.mark.asyncio
async def test_construct_model_no_validation(
    async_client: HarborAsyncClient,
    mocker: MockerFixture,
):
    c = async_client
    c.validate = False
    construct_spy = mocker.spy(UserResp, "construct")
    parse_spy = mocker.spy(UserResp, "parse_obj")

    # Extra field "foo" is added to the model
    m = c.construct_model(UserResp, {"username": "user1", "foo": "bar"})
    assert isinstance(m, UserResp)
    assert m.username == "user1"
    assert m.foo == "bar"
    assert construct_spy.call_count == 1
    assert parse_spy.call_count == 0

    # Invalid value for "username" if validation was enabled
    m = c.construct_model(UserResp, {"username": {}})
    assert m.username == {}
    assert construct_spy.call_count == 2
    assert parse_spy.call_count == 0


@pytest.mark.asyncio
async def test_client_no_validation_ctx_manager_get(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Test that the `no_validation` context manager temporarily disables validation."""

    resp = [
        {"username": "user1", "admin_role_in_auth": 123},
        {"username": "user2", "admin_role_in_auth": 456},
    ]
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        resp,
    )

    async_client.validate = True
    assert async_client.validate
    with async_client.no_validation():
        assert not async_client.validate
        users = await async_client.get_users()
    assert async_client.validate

    # No validation means we still get Pydantic models
    assert all(isinstance(u, UserResp) for u in users)
    assert users[0].username == "user1"
    assert users[0].admin_role_in_auth == 123
    assert users[1].username == "user2"
    assert users[1].admin_role_in_auth == 456


def test_client_no_validation_ctx_manager(
    async_client: HarborAsyncClient,
):
    async_client.validate = True
    assert async_client.validate
    with async_client.no_validation():
        assert not async_client.validate
    assert async_client.validate


def test_client_no_validation_ctx_manager_recover(
    async_client: HarborAsyncClient,
):
    """Test that the previous validation setting is recovered if an exception is raised
    in the `no_validation` context manager."""
    async_client.validate = True
    assert async_client.validate
    with pytest.raises(Exception):
        with async_client.no_validation():
            assert not async_client.validate
            raise Exception("test")
    assert async_client.validate


@pytest.mark.asyncio
async def test_construct_model_raw(
    async_client: HarborAsyncClient,
    mocker: MockerFixture,
):
    c = async_client
    c.raw = True
    construct_spy = mocker.spy(UserResp, "construct")
    parse_spy = mocker.spy(UserResp, "parse_obj")

    # Extra field "foo" is added to the model
    expect_resp = {"username": "user1", "foo": "bar"}
    m = c.construct_model(UserResp, expect_resp)
    assert m == expect_resp
    assert m["username"] == "user1"
    assert m["foo"] == "bar"
    assert construct_spy.call_count == 0
    assert parse_spy.call_count == 0


@pytest.mark.asyncio
async def test_construct_model_raw_is_list(
    async_client: HarborAsyncClient,
    mocker: MockerFixture,
):
    c = async_client
    c.raw = True
    construct_spy = mocker.spy(UserResp, "construct")
    parse_spy = mocker.spy(UserResp, "parse_obj")

    expect_resp = [{"username": "user1", "foo": "bar"}, {"username": "user2"}]
    m = c.construct_model(UserResp, expect_resp, is_list=True)
    assert m == expect_resp
    assert m[0]["username"] == "user1"
    assert m[0]["foo"] == "bar"
    assert m[1]["username"] == "user2"
    assert construct_spy.call_count == 0
    assert parse_spy.call_count == 0


@pytest.mark.asyncio
async def test_construct_model_raw_list_without_is_list(
    async_client: HarborAsyncClient,
    mocker: MockerFixture,
):
    """Receives list value, but is_list is set to False.
    Since we are in raw mode, this is not an error.
    """
    c = async_client
    c.raw = True
    construct_spy = mocker.spy(UserResp, "construct")
    parse_spy = mocker.spy(UserResp, "parse_obj")

    expect_resp = [{"username": "user1", "foo": "bar"}, {"username": "user2"}]
    m = c.construct_model(UserResp, expect_resp, is_list=False)
    assert m == expect_resp
    assert m[0]["username"] == "user1"
    assert m[0]["foo"] == "bar"
    assert m[1]["username"] == "user2"
    assert construct_spy.call_count == 0
    assert parse_spy.call_count == 0


@pytest.mark.asyncio
async def test_construct_model_raw_is_list_without_list(
    async_client: HarborAsyncClient,
    mocker: MockerFixture,
):
    """is_list is set to True, but receives non-list value.
    Since we are in raw mode, this is not an error.
    """
    c = async_client
    c.raw = True
    construct_spy = mocker.spy(UserResp, "construct")
    parse_spy = mocker.spy(UserResp, "parse_obj")

    expect_resp = {"username": "user1", "foo": "bar"}
    m = c.construct_model(UserResp, expect_resp, is_list=True)
    assert m == expect_resp
    assert m["username"] == "user1"
    assert m["foo"] == "bar"
    assert construct_spy.call_count == 0
    assert parse_spy.call_count == 0


def test_client_raw_mode_ctx_manager(
    async_client: HarborAsyncClient,
):
    async_client.raw = False
    assert not async_client.raw
    with async_client.raw_mode():
        assert async_client.raw
    assert not async_client.raw


def test_client_raw_mode_ctx_manager_recover(
    async_client: HarborAsyncClient,
):
    """Test that the previous raw setting is recovered if an exception is raised
    in the `raw_mode` context manager."""
    async_client.raw = False
    assert not async_client.raw
    with pytest.raises(Exception):
        with async_client.raw_mode():
            assert async_client.raw
            raise Exception("test")
    assert not async_client.raw


@pytest.mark.asyncio
async def test_client_raw_mode_ctx_manager_get(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Tests the `raw_mode` context manager with a GET request to a mock user endpoint."""
    async_client.raw = False
    assert not async_client.raw

    resp = [{"username": "user1", "foo": "bar"}, {"username": "user2"}]
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        resp,
    )

    with async_client.raw_mode():
        assert async_client.raw
        users = await async_client.get_users()
        assert users == resp  # raw mode returns the raw response

    assert not async_client.raw


@pytest.mark.asyncio
async def test_get_invalid_data(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    """Tests handling of data from the server that does not match the schema."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": {}}, {"username": "user2"}],
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    with pytest.raises(ValidationError) as e:
        await async_client.get_users()
    assert e.value.errors()[0]["loc"] == ("username",)
    assert len(e.value.errors()) == 1


@pytest.mark.asyncio
@given(errors_strategy)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_errors(
    async_client: HarborAsyncClient, httpserver: HTTPServer, errors: Errors
):
    """Tests handling of data from the server that does not match the schema."""
    httpserver.expect_oneshot_request("/api/v2.0/errorpath").respond_with_json(
        errors.dict(), status=500
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    with pytest.raises(StatusError) as exc_info:
        await async_client.get("/errorpath")
    assert exc_info is not None

    e = exc_info.value
    assert isinstance(e, StatusError)
    assert isinstance(e.errors, list)
    if e.errors:
        for error in e.errors:
            assert isinstance(error, Error)

    assert isinstance(e.__cause__, HTTPStatusError)
    assert e.__cause__.request.url == async_client.url + "/errorpath"
    assert e.__cause__.response.status_code == 500


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method",
    [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        # "HEAD"
        # "OPTIONS"
    ],
)
@pytest.mark.parametrize(
    "username,secret,credentials",
    [
        ("user", "secret", ""),
        ("", "", "credentials"),
        ("user", "secret", "credentials"),
        # ("", "", ""), # TODO: handle empty
    ],
)
async def test_authentication(
    httpserver: HTTPServer, method: str, username: str, secret: str, credentials: str
):
    """Tests handling of data from the server that does not match the schema."""

    client = HarborAsyncClient(
        url=httpserver.url_for("/api/v2.0"),
        username=username,
        secret=secret,
        basicauth=credentials,
    )

    # username/password takes precedence over credentials
    if username and secret:
        expect_credentials = get_basicauth(username, secret).get_secret_value()
    else:
        expect_credentials = credentials
    assert client.basicauth.get_secret_value() == expect_credentials

    # Set up HTTP server to expect a certain set of headers and a method
    httpserver.expect_oneshot_request(
        "/api/v2.0/foo",
        headers={
            "authorization": f"Basic {expect_credentials}",
            "accept": "application/json",
        },
        method=method,
    ).respond_with_data()

    if method == "GET":
        await client.get("/foo")
    elif method == "POST":
        await client.post("/foo", json={"foo": "bar"})
    elif method == "PUT":
        await client.put("/foo", json={"foo": "bar"})
    elif method == "PATCH":
        await client.patch("/foo", json={"foo": "bar"})
    elif method == "DELETE":
        await client.delete("/foo")


@pytest.mark.parametrize("url", ["https://localhost/api/v2.0", None])
@pytest.mark.parametrize(
    "username, secret, basicauth, credentials_file",
    [
        ("new_username", "new_secret", None, None),
        (None, None, "new_basicauth", None),
        (None, None, None, "new_credentials.json"),
    ],
)
def test_authenticate(
    tmp_path: Path,
    url: Optional[str],
    username: Optional[str],
    secret: Optional[str],
    basicauth: Optional[str],
    credentials_file: Optional[str],
) -> None:
    """Tests the authenticate method."""
    client = HarborAsyncClient(
        url="https://example.com/api/v2.0",
        username="username",
        secret="secret",
    )
    assert client.url == "https://example.com/api/v2.0"
    assert client.basicauth == get_basicauth("username", "secret")

    if credentials_file:
        credentials_file = tmp_path / credentials_file  # type: ignore
        with open(credentials_file, "w") as f:
            h = HarborAuthFile(
                name="credentials_username",
                secret="credentials_secret",
            )
            f.write(h.json())

    client.authenticate(
        url=url,
        username=username,
        secret=secret,
        basicauth=basicauth,
        credentials_file=credentials_file,
    )

    # URL should only be overwritten if new URL is not None
    if url:
        assert client.url == url
    else:
        # URL is still the same
        assert client.url == "https://example.com/api/v2.0"

    # Check that the basicauth is set correctly based on the arguments
    client_basicauth = client.basicauth.get_secret_value()
    if username and secret:
        assert client_basicauth == get_basicauth(username, secret).get_secret_value()
    elif basicauth:
        assert client_basicauth == basicauth
    elif credentials_file:
        assert (
            client_basicauth
            == get_basicauth(
                "credentials_username", "credentials_secret"
            ).get_secret_value()
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status_code",
    [400, 401, 403, 404, 412, 500],
)
@pytest.mark.parametrize(
    "method",
    [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        # "HEAD"
        # "OPTIONS"
    ],
)
async def test_exceptions(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    status_code: int,
    method: str,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/exceptions", method=method
    ).respond_with_data(status=status_code)

    async_client.url = httpserver.url_for("/api/v2.0")
    exceptions = {
        400: BadRequest,
        401: Unauthorized,
        403: Forbidden,
        404: NotFound,
        412: PreconditionFailed,
        500: InternalServerError,
    }
    with pytest.raises(exceptions[status_code]) as exc_info:
        if method == "GET":
            await async_client.get("/exceptions")
        elif method == "POST":
            await async_client.post("/exceptions", json={"foo": "bar"})
        elif method == "PUT":
            await async_client.put("/exceptions", json={"foo": "bar"})
        elif method == "PATCH":
            await async_client.patch("/exceptions", json={"foo": "bar"})
        elif method == "DELETE":
            await async_client.delete("/exceptions")
    assert exc_info.value.status_code == status_code


async def test_cookies(async_client: HarborAsyncClient, httpserver: HTTPServer):
    """Test the client to make sure cookies are properly discarded after each request."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}],
        status=200,
        headers={"Set-Cookie": "foo=bar"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.get_users()
    assert async_client.client.cookies.get("foo") is None
    assert len(async_client.client.cookies) == 0
