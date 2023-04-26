from pytest_httpserver import HTTPServer

from harborapi import HarborAsyncClient


async def test_response_log(async_client: HarborAsyncClient, httpserver: HTTPServer):
    """Tests handling of data from the server that does not match the schema."""
    httpserver.expect_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}], status=200
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.get_users()
    await async_client.get_users()
    await async_client.get_users()
    assert len(async_client.response_log) == 3
    # check default maxlen
    assert async_client.response_log.entries.maxlen is None

    # test iteration + indexing
    for i, response in enumerate(async_client.response_log):
        assert response == async_client.response_log[i]
        assert response.status_code == 200
        # ignore params in case our defaults change in the future
        base_url = str(response.url).split("?")[0]
        assert base_url == async_client.url + "/users"
        assert response.method == "GET"
        assert response.response_size > 0

    # Resize log down to a smaller max size
    oldest_response = async_client.response_log[0]
    async_client.response_log.resize(2)
    assert len(async_client.response_log) == 2
    assert oldest_response not in async_client.response_log

    # Resize up to a larger max size
    async_client.response_log.resize(5)
    assert len(async_client.response_log) == 2

    # Clear the log
    async_client.response_log.clear()
    assert len(async_client.response_log) == 0
    assert async_client.response_log.entries.maxlen == 5


async def test_last_response(async_client: HarborAsyncClient, httpserver: HTTPServer):
    """Test retrieving the last logged response."""
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [{"username": "user1"}, {"username": "user2"}], status=200
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.get_users()
    last_response = async_client.last_response
    assert last_response is not None
    assert last_response.status_code == 200
    assert last_response.url == async_client.url + "/users?page=1&page_size=10"
    assert last_response.method == "GET"
    assert last_response.response_size > 0
    async_client.response_log.clear()
    assert async_client.last_response is None
