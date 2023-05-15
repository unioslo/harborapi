import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Search


@pytest.mark.asyncio
@given(st.builds(Search))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_search_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    search: Search,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/search", method="GET", query_string={"q": "testproj"}
    ).respond_with_data(search.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.search("testproj")
    assert resp == search


def test_search_chart() -> None:
    """/search returning charts as a separate search result was deprecated in #18265 (https://github.com/goharbor/harbor/pull/18265)

    This test ensures that we can parse the response from /search even if
    it includes charts."""

    data = {
        "chart": [
            {
                "Chart": {
                    "apiVersion": "v2",
                    "appVersion": "1.23.1",
                    "description": "NGINX Open Source is a web server that can be also used as a reverse proxy, load balancer, and HTTP cache. Recommended for high-demanding sites due to its ability to provide faster content.",
                    "engine": None,
                    "home": "https://github.com/bitnami/charts/tree/master/bitnami/nginx",
                    "icon": "https://bitnami.com/assets/stacks/nginx/img/nginx-stack-220x234.png",
                    "keywords": ["nginx", "http", "web", "www", "reverse proxy"],
                    "name": "myproject/nginx",
                    "sources": [
                        "https://github.com/bitnami/containers/tree/main/bitnami/nginx",
                        "https://www.nginx.org",
                    ],
                    "version": "13.1.6",
                    "created": "2023-02-03T09:38:19.867594256Z",
                    "digest": "56663051192d296847e60ea81cebe03a26a703c3c6eef8f976509f80dc5e87ea",
                    "urls": ["myproject/charts/nginx-13.1.6.tgz"],
                    "labels": None,
                },
                "Name": "myproject/nginx",
            }
        ],
        "project": [],
        "repository": [],
    }

    s = Search(**data)
    assert s.project == []
    assert s.repository == []
    # we accept extra fields for compatibility:
    assert s.chart == data["chart"]
